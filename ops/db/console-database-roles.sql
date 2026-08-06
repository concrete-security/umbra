-- Reference Postgres roles and grants for the Umbra Console (docs/specs/console.md §15.4, §15.5).
-- Run as a superuser. Set UMBRA_DB to your database name (e.g. umbra) before applying:
--   psql -v UMBRA_DB=umbra -f ops/db/console-database-roles.sql
--
-- Note: §15.5's privilege table lists audit_anchors alongside the other append-only tables for
-- umbra_console_app, but the bullets under "The runtime role MUST NOT" forbid any read or
-- write on audit_anchors. This script follows the bullets: anchor INSERTs use umbra_console_anchor
-- (separate DSN / credential). Until the Console connects as umbra_console_app for DATABASE_URL,
-- you will still use a bootstrap superuser or must route publish_audit_anchor through the anchor role.

\set ON_ERROR_STOP on

CREATE ROLE umbra_console_app NOINHERIT LOGIN PASSWORD 'replace-me-app';
CREATE ROLE umbra_console_migrate NOINHERIT LOGIN PASSWORD 'replace-me-migrate';
CREATE ROLE umbra_console_anchor NOINHERIT LOGIN PASSWORD 'replace-me-anchor';
CREATE ROLE umbra_console_prune NOINHERIT LOGIN PASSWORD 'replace-me-prune';
CREATE ROLE umbra_console_redactor NOINHERIT LOGIN PASSWORD 'replace-me-redactor';

GRANT CONNECT ON DATABASE :"UMBRA_DB" TO umbra_console_app;
GRANT CONNECT ON DATABASE :"UMBRA_DB" TO umbra_console_migrate;
GRANT CONNECT ON DATABASE :"UMBRA_DB" TO umbra_console_anchor;
GRANT CONNECT ON DATABASE :"UMBRA_DB" TO umbra_console_prune;
GRANT CONNECT ON DATABASE :"UMBRA_DB" TO umbra_console_redactor;

\c :"UMBRA_DB"

GRANT USAGE ON ALL TYPES IN SCHEMA public TO umbra_console_app;
GRANT USAGE ON ALL TYPES IN SCHEMA public TO umbra_console_migrate;

GRANT USAGE ON SCHEMA public TO umbra_console_app;
GRANT USAGE ON SCHEMA public TO umbra_console_migrate;
GRANT USAGE ON SCHEMA public TO umbra_console_anchor;
GRANT USAGE ON SCHEMA public TO umbra_console_prune;
GRANT USAGE ON SCHEMA public TO umbra_console_redactor;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO umbra_console_migrate;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO umbra_console_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO umbra_console_migrate;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO umbra_console_app;

REVOKE ALL ON TABLE audit_events FROM umbra_console_app;
REVOKE ALL ON TABLE audit_anchors FROM umbra_console_app;
REVOKE ALL ON TABLE traffic_logs FROM umbra_console_app;
REVOKE ALL ON TABLE traffic_log_batches FROM umbra_console_app;

GRANT SELECT, INSERT ON audit_events TO umbra_console_app;
GRANT SELECT, INSERT ON traffic_logs TO umbra_console_app;
GRANT SELECT, INSERT ON traffic_log_batches TO umbra_console_app;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM umbra_console_anchor;
GRANT SELECT ON audit_events TO umbra_console_anchor;
GRANT SELECT, INSERT ON audit_anchors TO umbra_console_anchor;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM umbra_console_prune;
GRANT DELETE ON traffic_logs TO umbra_console_prune;
GRANT DELETE ON traffic_log_batches TO umbra_console_prune;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM umbra_console_redactor;
GRANT UPDATE (actor_email, "before", "after", prev_hash, row_hash) ON audit_events TO umbra_console_redactor;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO umbra_console_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO umbra_console_migrate;
ALTER DEFAULT PRIVILEGES FOR ROLE umbra_console_migrate IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO umbra_console_migrate;
