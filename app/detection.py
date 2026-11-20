"""Account takeover rules. The same rules are implemented in sql/03_detection_rules.sql.
Sample mode runs the Python rules below; Snowflake mode reads hits from the SQL rule views.

Each rule looks only at the detection window (2026-10-02 onwards) and fires at most once
per customer. A customer's alert score is the sum of the weights of the rules that fired.
These are illustrative rules and thresholds, not a recommended detection standard.
"""

import math

import pandas as pd

WINDOW_START = pd.Timestamp("2026-10-02")
AS_OF = pd.Timestamp("2026-11-01")

RULES = {
    "takeover_sequence": "Credential change, new payee, transfer to it within 24 hours",
    "impossible_travel": "Consecutive logins faster than 900 km/h",
    "new_device_country": "New device and new country, then a transaction in that session",
    "mfa_fatigue": "MFA approved after 5+ denials in 10 minutes",
    "credential_stuffing": "Login from an IP that failed against 8+ customers",
    "unusual_amount": "Transfer of $1,000+ above 3x the customer's baseline median",
}
LABELS = {
    "takeover_sequence": "Takeover sequence", "impossible_travel": "Impossible travel",
    "new_device_country": "New device + country", "mfa_fatigue": "MFA fatigue",
    "credential_stuffing": "Credential stuffing", "unusual_amount": "Unusual amount",
}
DEFAULT_WEIGHTS = {"takeover_sequence": 50, "impossible_travel": 30, "new_device_country": 25,
                   "mfa_fatigue": 35, "credential_stuffing": 20, "unusual_amount": 15}
DEFAULT_THRESHOLD = 40

SPEED_KMH, MIN_KM = 900, 500
MFA_DENIALS, MFA_MINUTES = 5, 10
STUFFING_CUSTOMERS = 8
AMOUNT_MULTIPLE, AMOUNT_MIN = 3, 1000


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance; same formula and Earth radius as Snowflake HAVERSINE."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def prepare(frames: dict) -> dict:
    out = {}
    for name, col in (("identity_events", "event_ts"), ("account_changes", "change_ts"), ("transactions", "txn_ts")):
        df = frames[name].copy()
        df[col] = pd.to_datetime(df[col])
        for c in ("session_id", "payee_id"):
            if c in df:
                df[c] = df[c].fillna("").astype(str)
        out[name] = df
    cust = frames["customers"].copy()
    cust["confirmed_ato"] = cust["confirmed_ato"].astype(str).str.upper().eq("TRUE")
    out["customers"] = cust
    return out


def _takeover_sequence(d) -> dict:
    ch = d["account_changes"][d["account_changes"]["change_ts"] >= WINDOW_START]
    tx = d["transactions"][d["transactions"]["txn_ts"] >= WINDOW_START]
    ev = pd.concat([
        pd.DataFrame({"customer_id": ch["customer_id"], "ts": ch["change_ts"], "ord": ch["change_id"],
                      "kind": ch["change_type"], "payee_id": ch["payee_id"], "amount": 0}),
        pd.DataFrame({"customer_id": tx["customer_id"], "ts": tx["txn_ts"], "ord": tx["txn_id"],
                      "kind": "TRANSFER", "payee_id": tx["payee_id"], "amount": tx["amount"]}),
    ]).sort_values(["customer_id", "ts", "ord"])
    hits = {}
    for cust, g in ev.groupby("customer_id", sort=False):
        rows = list(g.itertuples(index=False))
        found = None
        for i, c in enumerate(rows):
            if c.kind not in ("PASSWORD_RESET", "PHONE_CHANGE"):
                continue
            for j in range(i + 1, len(rows)):
                a = rows[j]
                if a.kind != "PAYEE_ADDED":
                    continue
                for t in rows[j + 1:]:
                    if t.kind == "TRANSFER" and t.payee_id == a.payee_id and (t.ts - c.ts).total_seconds() <= 86400:
                        found = f"{c.kind.replace('_', ' ').lower()} {c.ts:%b %d %H:%M}, payee {a.payee_id} added, ${t.amount:,} sent {t.ts:%H:%M}"
                        break
                if found:
                    break
            if found:
                break
        if found:
            hits[cust] = found
    return hits


def _logins(d):
    ie = d["identity_events"]
    return ie[ie["event_type"] == "LOGIN_SUCCESS"].sort_values(["customer_id", "event_ts", "event_id"])


def _impossible_travel(d) -> dict:
    hits = {}
    lg = _logins(d)
    for cust, g in lg.groupby("customer_id", sort=False):
        prev = None
        for r in g.itertuples(index=False):
            if prev is not None and r.event_ts >= WINDOW_START:
                km = haversine_km(prev.latitude, prev.longitude, r.latitude, r.longitude)
                hours = max((r.event_ts - prev.event_ts).total_seconds() / 3600, 1 / 60)
                if km >= MIN_KM and km / hours > SPEED_KMH and cust not in hits:
                    hits[cust] = f"{prev.city} to {r.city}: {km:,.0f} km in {hours * 60:,.0f} minutes"
            prev = r
    return hits


def _new_device_country(d) -> dict:
    ie = d["identity_events"].sort_values(["customer_id", "event_ts", "event_id"])
    first_dev = ie.groupby(["customer_id", "device_id"])["event_id"].first()
    first_cty = ie.groupby(["customer_id", "country"])["event_id"].first()
    tx_sessions = set(zip(d["transactions"]["customer_id"], d["transactions"]["session_id"]))
    hits = {}
    for r in _logins(d).itertuples(index=False):
        if (r.event_ts >= WINDOW_START and first_dev[(r.customer_id, r.device_id)] == r.event_id
                and first_cty[(r.customer_id, r.country)] == r.event_id
                and (r.customer_id, r.session_id) in tx_sessions and r.customer_id not in hits):
            hits[r.customer_id] = f"first login from device {r.device_id} in {r.city}, {r.country}, then a payment"
    return hits


def _mfa_fatigue(d) -> dict:
    ie = d["identity_events"]
    ie = ie[ie["event_ts"] >= WINDOW_START]
    denies = ie[ie["event_type"] == "MFA_DENY"]
    hits = {}
    for r in ie[ie["event_type"] == "MFA_APPROVE"].sort_values(["event_ts", "event_id"]).itertuples(index=False):
        n = ((denies["customer_id"] == r.customer_id) & (denies["event_ts"] < r.event_ts)
             & (denies["event_ts"] >= r.event_ts - pd.Timedelta(minutes=MFA_MINUTES))).sum()
        if n >= MFA_DENIALS and r.customer_id not in hits:
            hits[r.customer_id] = f"{n} MFA denials then an approval at {r.event_ts:%b %d %H:%M}"
    return hits


def _credential_stuffing(d) -> dict:
    ie = d["identity_events"]
    ie = ie[ie["event_ts"] >= WINDOW_START]
    fails = ie[ie["event_type"] == "LOGIN_FAIL"].groupby("ip_address")["customer_id"].nunique()
    bad = fails[fails >= STUFFING_CUSTOMERS]
    hits = {}
    ok = ie[(ie["event_type"] == "LOGIN_SUCCESS") & ie["ip_address"].isin(bad.index)]
    for r in ok.sort_values(["event_ts", "event_id"]).itertuples(index=False):
        hits.setdefault(r.customer_id, f"login from {r.ip_address}, which failed against {bad[r.ip_address]} customers")
    return hits


def _unusual_amount(d) -> dict:
    tx = d["transactions"]
    med = tx[tx["txn_ts"] < WINDOW_START].groupby("customer_id")["amount"].median()
    hits = {}
    for r in tx[tx["txn_ts"] >= WINDOW_START].sort_values(["txn_ts", "txn_id"]).itertuples(index=False):
        m = med.get(r.customer_id)
        if m is not None and r.amount >= AMOUNT_MIN and r.amount > AMOUNT_MULTIPLE * m:
            hits.setdefault(r.customer_id, f"${r.amount:,} against a baseline median of ${math.floor(m + 0.5):,}")  # round half up, like SQL
    return hits


RULE_FUNCS = {
    "takeover_sequence": _takeover_sequence, "impossible_travel": _impossible_travel,
    "new_device_country": _new_device_country, "mfa_fatigue": _mfa_fatigue,
    "credential_stuffing": _credential_stuffing, "unusual_amount": _unusual_amount,
}


def evaluate(d: dict, hits: dict | None = None) -> pd.DataFrame:
    """One row per customer that fired at least one rule: a 0/1 column and an evidence column per rule.

    hits is {rule: {customer_id: evidence}} from the SQL views; without it the Python rules run (sample mode).
    """
    res = hits if hits is not None else {r: f(d) for r, f in RULE_FUNCS.items()}
    custs = sorted(set().union(*[set(h) for h in res.values()]))
    out = pd.DataFrame({"customer_id": custs})
    for r, h in res.items():
        out[r] = out["customer_id"].map(lambda c: int(c in h))
        out[f"{r}_why"] = out["customer_id"].map(lambda c: h.get(c, ""))
    return out.merge(d["customers"], on="customer_id", how="left")


def score(flags: pd.DataFrame, weights: dict | None = None) -> pd.DataFrame:
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    out = flags.copy()
    out["alert_score"] = sum(out[r] * w[r] for r in RULES)
    out["rules_fired"] = sum(out[r] for r in RULES)
    out = out.sort_values(["alert_score", "rules_fired", "customer_id"], ascending=[False, False, True])
    out["alert_rank"] = range(1, len(out) + 1)
    out["rules"] = out.apply(lambda row: ", ".join(LABELS[r] for r in RULES if row[r]), axis=1)
    return out.reset_index(drop=True)


def rule_performance(scored: pd.DataFrame, threshold: int, total_ato: int) -> pd.DataFrame:
    rows = []
    for r in RULES:
        hit = scored[scored[r] == 1]
        tp = int(hit["confirmed_ato"].sum())
        rows.append({"Rule": LABELS[r], "Customers flagged": len(hit), "Confirmed takeovers": tp,
                     "False positives": len(hit) - tp,
                     "Precision": round(tp / len(hit), 2) if len(hit) else None,
                     "Recall": round(tp / total_ato, 2) if total_ato else None})
    alerts = scored[scored["alert_score"] >= threshold]
    tp = int(alerts["confirmed_ato"].sum())
    rows.append({"Rule": f"Alerts (score >= {threshold})", "Customers flagged": len(alerts), "Confirmed takeovers": tp,
                 "False positives": len(alerts) - tp, "Precision": round(tp / len(alerts), 2) if len(alerts) else None,
                 "Recall": round(tp / total_ato, 2) if total_ato else None})
    return pd.DataFrame(rows)


def timeline(d: dict, customer_id: str) -> pd.DataFrame:
    ie = d["identity_events"][d["identity_events"]["customer_id"] == customer_id]
    ch = d["account_changes"][d["account_changes"]["customer_id"] == customer_id]
    tx = d["transactions"][d["transactions"]["customer_id"] == customer_id]
    parts = [
        pd.DataFrame({"ts": ie["event_ts"], "ord": ie["event_id"], "type": ie["event_type"],
                      "detail": ie["city"] + ", " + ie["country"] + " · " + ie["ip_address"] + " · " + ie["device_id"],
                      "session": ie["session_id"]}),
        pd.DataFrame({"ts": ch["change_ts"], "ord": ch["change_id"], "type": ch["change_type"],
                      "detail": ch["payee_id"].map(lambda p: f"payee {p}" if p else ""), "session": ch["session_id"]}),
        pd.DataFrame({"ts": tx["txn_ts"], "ord": tx["txn_id"], "type": "TRANSFER",
                      "detail": "$" + tx["amount"].map("{:,}".format) + " to " + tx["payee_id"], "session": tx["session_id"]}),
    ]
    return pd.concat(parts).sort_values(["ts", "ord"]).reset_index(drop=True)


def case_summary(row) -> str:
    """Templated case summary used in sample mode (live mode uses Cortex AI_COMPLETE)."""
    fired = [r for r in RULES if row[r]]
    lines = "; ".join(f"{LABELS[r].lower()}: {row[f'{r}_why']}" for r in fired)
    strong = row["takeover_sequence"] or row["mfa_fatigue"] or (row["impossible_travel"] and row["new_device_country"])
    action = ("Recommend an immediate hold on outbound payments, contacting the customer on their verified "
              "number from before any recent change, and resetting credentials." if strong else
              "Recommend contacting the customer to confirm the activity before taking further action.")
    return f"{row['customer_name']} ({row['customer_id']}) triggered {len(fired)} rule(s): {lines}. {action}"
