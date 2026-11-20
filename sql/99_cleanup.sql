-- Account Takeover Detection: cleanup. Removes everything the setup created.
-- ATO_DEMO_ROLE owns the database (see 01_setup.sql), so it drops the database first.
USE ROLE ATO_DEMO_ROLE;
DROP DATABASE IF EXISTS ACCOUNT_TAKEOVER;   -- tables, rule views, alerts view, case summaries
USE ROLE ACCOUNTADMIN;
DROP WAREHOUSE IF EXISTS ATO_DEMO_WH;
DROP ROLE IF EXISTS ATO_DEMO_ROLE;
