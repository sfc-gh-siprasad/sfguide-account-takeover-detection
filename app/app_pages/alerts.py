import streamlit as st

import common
import detection

ctx = common.context()
scored = ctx["scored"]

st.title("Account takeover alert queue")
st.caption("Detection window 2 October to 1 November 2026 · customers ranked by the rules they triggered")
with st.container(horizontal=True):
    if ctx["live"]:
        st.badge("Rules from Snowflake SQL views", icon=":material/cloud_done:", color="blue")
    else:
        st.badge("Sample data", icon=":material/database:", color="gray")
    if not ctx["default_weights"]:
        st.badge("Custom weights applied", icon=":material/tune:", color="orange")

threshold = st.session_state.get("threshold", detection.DEFAULT_THRESHOLD)
alerts = scored[scored["alert_score"] >= threshold]
with st.container(horizontal=True):
    st.metric("Customers with a rule hit", f"{len(scored):,}", border=True)
    st.metric(f"Alerts (score {threshold}+)", f"{len(alerts):,}", border=True)
    st.metric("Alerts that are confirmed takeovers", f"{int(alerts['confirmed_ato'].sum())}", border=True,
              help="From the synthetic ground-truth label, which stands in for closed investigations")
    st.metric("Takeovers caught", f"{int(alerts['confirmed_ato'].sum())} of {ctx['total_ato']}", border=True)

with st.expander("Tune the rule weights and alert threshold", icon=":material/tune:"):
    st.caption("Points added when a rule fires. The queue re-ranks as you change them. "
               "In Snowflake these live in the RULE_WEIGHTS table.")
    w = common.weights()
    cols = st.columns(3)
    for i, (key, label) in enumerate(detection.LABELS.items()):
        w[key] = cols[i % 3].number_input(label, min_value=0, max_value=100, value=int(w[key]), step=5,
                                          key=f"w_{key}", help=detection.RULES[key])
    st.slider("Alert threshold (score)", 5, 150, step=5, key="threshold", value=detection.DEFAULT_THRESHOLD)
    if st.button("Reset to defaults", icon=":material/restart_alt:"):
        st.session_state.weights = dict(detection.DEFAULT_WEIGHTS)
        for key in detection.LABELS:
            st.session_state.pop(f"w_{key}", None)
        st.session_state.pop("threshold", None)
        st.rerun()

rule_pick = st.pills("Show customers who triggered", list(detection.LABELS.values()), selection_mode="multi",
                     key="rule_pick")
only_alerts = st.toggle("Alerts only", value=True, key="only_alerts")
view = alerts if only_alerts else scored
if rule_pick:
    keys = [k for k, v in detection.LABELS.items() if v in rule_pick]
    view = view[view[keys].sum(axis=1) > 0]

with st.container(border=True):
    st.subheader("Ranked alerts")
    event = st.dataframe(
        view[["alert_rank", "customer_id", "customer_name", "segment", "home_city", "rules_fired", "rules", "alert_score"]],
        hide_index=True, on_select="rerun", selection_mode="single-row", key="alert_table",
        alt="Ranked account takeover alerts; select a row to open the case timeline",
        column_config={
            "alert_rank": st.column_config.NumberColumn("Rank"), "customer_id": "Customer",
            "customer_name": "Name", "segment": "Segment", "home_city": "Home city",
            "rules_fired": st.column_config.NumberColumn("Rules"), "rules": "Rules triggered",
            "alert_score": st.column_config.ProgressColumn("Score", min_value=0,
                                                            max_value=int(sum(w.values())), format="%d"),
        },
    )
    st.caption(f"{len(view):,} customers. Select a row, then open the case timeline.")
    if event.selection.rows:
        st.session_state.customer_id = view.iloc[event.selection.rows[0]]["customer_id"]
        st.page_link("app_pages/case.py", label=f"Open case for {st.session_state.customer_id}",
                     icon=":material/arrow_forward:")

with st.container(border=True):
    st.subheader("Rule hits")
    counts = [{"Rule": detection.LABELS[r], "Customers": int(scored[r].sum())} for r in detection.RULES]
    st.bar_chart(counts, x="Rule", y="Customers", horizontal=True, sort="-Customers", x_label="", y_label="Customers",
                 alt="Number of customers that triggered each rule")
