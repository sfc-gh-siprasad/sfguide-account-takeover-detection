-- Account Takeover Detection: the six rules as views, plus the scored alert view.
-- Same rules as app/detection.py. The detection window starts 2026-10-02 to match the
-- synthetic data; for real use replace it with DATEADD('day', -30, CURRENT_DATE()).
-- These are views, not Dynamic Tables: Dynamic Tables do not support MATCH_RECOGNIZE.
-- Each RULE_* view returns one row per flagged customer with a WHY evidence column; the app
-- reads these views in Snowflake mode and applies the on-screen weights to them.
USE ROLE ATO_DEMO_ROLE;
USE WAREHOUSE ATO_DEMO_WH;
USE SCHEMA ACCOUNT_TAKEOVER.DATA;

-- 1. Takeover sequence: password/phone change -> new payee -> transfer to that payee within 24 hours.
-- Each partition is one customer and one newly added payee, holding the customer's credential
-- changes plus that payee's add and transfers. PATTERN (C A N* T) takes the change right before
-- the add and the first transfer after it (other changes may sit in between), the tightest sequence.
CREATE OR REPLACE VIEW RULE_TAKEOVER_SEQUENCE AS
WITH win AS (SELECT '2026-10-02'::TIMESTAMP_NTZ AS start_ts),
adds AS (
  SELECT customer_id, payee_id FROM ACCOUNT_CHANGES, win
  WHERE change_type = 'PAYEE_ADDED' AND change_ts >= start_ts
),
stream AS (
  SELECT a.customer_id, a.payee_id AS payee_key, c.change_ts AS event_ts, c.change_id AS ord_id,
         c.change_type AS kind, 0 AS amount
  FROM adds a JOIN ACCOUNT_CHANGES c ON c.customer_id = a.customer_id, win
  WHERE c.change_ts >= start_ts
    AND (c.change_type IN ('PASSWORD_RESET', 'PHONE_CHANGE')
         OR (c.change_type = 'PAYEE_ADDED' AND c.payee_id = a.payee_id))
  UNION ALL
  SELECT a.customer_id, a.payee_id, t.txn_ts, t.txn_id, 'TRANSFER', t.amount
  FROM adds a JOIN TRANSACTIONS t ON t.customer_id = a.customer_id AND t.payee_id = a.payee_id, win
  WHERE t.txn_ts >= start_ts
)
SELECT customer_id, MIN(cred_change_ts) AS cred_change_ts, MIN(new_payee) AS new_payee,
       MAX(transfer_amount) AS transfer_amount,
       MIN_BY(LOWER(REPLACE(cred_change, '_', ' ')) || ' ' || TO_CHAR(cred_change_ts, 'Mon DD HH24:MI')
              || ', payee ' || new_payee || ' added, $' || TRIM(TO_CHAR(transfer_amount, '999,999,999,990'))
              || ' sent ' || TO_CHAR(transfer_ts, 'HH24:MI'), cred_change_ts) AS why
FROM stream
  MATCH_RECOGNIZE (
    PARTITION BY customer_id, payee_key
    ORDER BY event_ts, ord_id
    MEASURES C.event_ts AS cred_change_ts, C.kind AS cred_change, A.ord_id AS add_id,
             payee_key AS new_payee, T.event_ts AS transfer_ts, T.amount AS transfer_amount
    ONE ROW PER MATCH
    AFTER MATCH SKIP PAST LAST ROW
    PATTERN (C A N* T)
    DEFINE C AS kind IN ('PASSWORD_RESET', 'PHONE_CHANGE'),
           A AS kind = 'PAYEE_ADDED',
           N AS kind <> 'TRANSFER',
           T AS kind = 'TRANSFER'
  )
WHERE DATEDIFF('second', cred_change_ts, transfer_ts) <= 86400
GROUP BY customer_id;

-- 2. Impossible travel: consecutive successful logins at more than 900 km/h and at least 500 km apart.
CREATE OR REPLACE VIEW RULE_IMPOSSIBLE_TRAVEL AS
WITH l AS (
  SELECT customer_id, event_ts, city, latitude, longitude,
         LAG(event_ts)  OVER (PARTITION BY customer_id ORDER BY event_ts, event_id) AS prev_ts,
         LAG(city)      OVER (PARTITION BY customer_id ORDER BY event_ts, event_id) AS prev_city,
         LAG(latitude)  OVER (PARTITION BY customer_id ORDER BY event_ts, event_id) AS prev_lat,
         LAG(longitude) OVER (PARTITION BY customer_id ORDER BY event_ts, event_id) AS prev_lon
  FROM IDENTITY_EVENTS WHERE event_type = 'LOGIN_SUCCESS'
),
s AS (
  SELECT *, HAVERSINE(prev_lat, prev_lon, latitude, longitude) AS km,
         GREATEST(DATEDIFF('second', prev_ts, event_ts) / 3600, 1 / 60) AS hours
  FROM l WHERE prev_ts IS NOT NULL AND event_ts >= '2026-10-02'::TIMESTAMP_NTZ
)
SELECT customer_id, MAX(km / hours) AS max_kmh,
       MIN_BY(prev_city || ' to ' || city || ': ' || TRIM(TO_CHAR(ROUND(km), '999,999,990')) || ' km in '
              || TRIM(TO_CHAR(ROUND(hours * 60), '999,999,990')) || ' minutes', event_ts) AS why
FROM s WHERE km >= 500 AND km / hours > 900
GROUP BY customer_id;

-- 3. New device and new country on a login, then a transaction in that session.
CREATE OR REPLACE VIEW RULE_NEW_DEVICE_COUNTRY AS
WITH e AS (
  SELECT *,
    ROW_NUMBER() OVER (PARTITION BY customer_id, device_id ORDER BY event_ts, event_id) AS dev_seq,
    ROW_NUMBER() OVER (PARTITION BY customer_id, country   ORDER BY event_ts, event_id) AS cty_seq
  FROM IDENTITY_EVENTS
)
SELECT e.customer_id, MIN(e.event_ts) AS login_ts, MIN(e.country) AS country,
       MIN_BY('first login from device ' || e.device_id || ' in ' || e.city || ', ' || e.country
              || ', then a payment', e.event_ts) AS why
FROM e
WHERE e.event_type = 'LOGIN_SUCCESS' AND e.event_ts >= '2026-10-02'::TIMESTAMP_NTZ
  AND e.dev_seq = 1 AND e.cty_seq = 1
  AND EXISTS (SELECT 1 FROM TRANSACTIONS t WHERE t.customer_id = e.customer_id AND t.session_id = e.session_id)
GROUP BY e.customer_id;

-- 4. MFA fatigue: an approval preceded by 5+ denials in the previous 10 minutes.
CREATE OR REPLACE VIEW RULE_MFA_FATIGUE AS
SELECT a.customer_id, MAX(n) AS denials,
       MIN_BY(n || ' MFA denials then an approval at ' || TO_CHAR(a.event_ts, 'Mon DD HH24:MI'), a.event_ts) AS why
FROM (
  SELECT ap.customer_id, ap.event_id, ap.event_ts, COUNT(d.event_id) AS n
  FROM IDENTITY_EVENTS ap
  JOIN IDENTITY_EVENTS d
    ON d.customer_id = ap.customer_id AND d.event_type = 'MFA_DENY'
   AND d.event_ts < ap.event_ts AND d.event_ts >= DATEADD('minute', -10, ap.event_ts)
   AND d.event_ts >= '2026-10-02'::TIMESTAMP_NTZ
  WHERE ap.event_type = 'MFA_APPROVE' AND ap.event_ts >= '2026-10-02'::TIMESTAMP_NTZ
  GROUP BY ap.customer_id, ap.event_id, ap.event_ts
) a
WHERE n >= 5
GROUP BY a.customer_id;

-- 5. Credential stuffing: a successful login from an IP that failed against 8+ distinct customers.
CREATE OR REPLACE VIEW RULE_CREDENTIAL_STUFFING AS
WITH w AS (SELECT * FROM IDENTITY_EVENTS WHERE event_ts >= '2026-10-02'::TIMESTAMP_NTZ),
bad AS (
  SELECT ip_address, COUNT(DISTINCT customer_id) AS customers_failed
  FROM w WHERE event_type = 'LOGIN_FAIL' GROUP BY ip_address HAVING COUNT(DISTINCT customer_id) >= 8
)
SELECT w.customer_id, MIN(w.ip_address) AS ip_address, MAX(bad.customers_failed) AS customers_failed,
       MIN_BY('login from ' || w.ip_address || ', which failed against ' || bad.customers_failed || ' customers',
              w.event_ts) AS why
FROM w JOIN bad ON bad.ip_address = w.ip_address
WHERE w.event_type = 'LOGIN_SUCCESS'
GROUP BY w.customer_id;

-- 6. Unusual amount: a transfer of $1,000+ above 3x the customer's baseline median.
CREATE OR REPLACE VIEW RULE_UNUSUAL_AMOUNT AS
WITH base AS (
  SELECT customer_id, MEDIAN(amount) AS baseline_median
  FROM TRANSACTIONS WHERE txn_ts < '2026-10-02'::TIMESTAMP_NTZ GROUP BY customer_id
)
SELECT t.customer_id, MAX(t.amount) AS max_amount, MAX(b.baseline_median) AS baseline_median,
       MIN_BY('$' || TRIM(TO_CHAR(t.amount, '999,999,999,990')) || ' against a baseline median of $'
              || TRIM(TO_CHAR(ROUND(b.baseline_median), '999,999,999,990')), t.txn_ts) AS why
FROM TRANSACTIONS t JOIN base b ON b.customer_id = t.customer_id
WHERE t.txn_ts >= '2026-10-02'::TIMESTAMP_NTZ AND t.amount >= 1000 AND t.amount > 3 * b.baseline_median
GROUP BY t.customer_id;

-- Scored alerts: one row per customer that fired at least one rule, weighted by RULE_WEIGHTS.
CREATE OR REPLACE VIEW ATO_ALERTS AS
WITH f AS (
  SELECT customer_id, 'takeover_sequence' AS rule_name FROM RULE_TAKEOVER_SEQUENCE
  UNION ALL SELECT customer_id, 'impossible_travel'   FROM RULE_IMPOSSIBLE_TRAVEL
  UNION ALL SELECT customer_id, 'new_device_country'  FROM RULE_NEW_DEVICE_COUNTRY
  UNION ALL SELECT customer_id, 'mfa_fatigue'         FROM RULE_MFA_FATIGUE
  UNION ALL SELECT customer_id, 'credential_stuffing' FROM RULE_CREDENTIAL_STUFFING
  UNION ALL SELECT customer_id, 'unusual_amount'      FROM RULE_UNUSUAL_AMOUNT
),
s AS (
  SELECT f.customer_id, SUM(w.points) AS alert_score, COUNT(*) AS rules_fired,
         ARRAY_TO_STRING(ARRAY_AGG(f.rule_name) WITHIN GROUP (ORDER BY f.rule_name), ', ') AS rules
  FROM f JOIN RULE_WEIGHTS w ON w.rule_name = f.rule_name
  GROUP BY f.customer_id
)
SELECT s.*, c.customer_name, c.segment, c.home_city, c.confirmed_ato,
       ROW_NUMBER() OVER (ORDER BY alert_score DESC, rules_fired DESC, s.customer_id) AS alert_rank
FROM s JOIN CUSTOMERS c ON c.customer_id = s.customer_id;
