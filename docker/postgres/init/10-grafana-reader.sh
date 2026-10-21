#!/bin/sh
# Creates a read-only role for Grafana. Runs once, when the data volume is initialised.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v reader_password="$GRAFANA_DB_PASSWORD" <<'SQL'
CREATE ROLE grafana_reader LOGIN PASSWORD :'reader_password';
GRANT CONNECT ON DATABASE pulse TO grafana_reader;
GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_reader;
-- Tables and views created later by the collector's migrations (owned by "pulse").
ALTER DEFAULT PRIVILEGES FOR ROLE pulse IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader;
ALTER ROLE grafana_reader SET default_transaction_read_only = on;
ALTER ROLE grafana_reader SET statement_timeout = '30s';
SQL
