-- Runs once, when the local Postgres volume is created.
--
-- Deliberately almost empty. Schemas and roles per service are made by dbinit
-- on every start, not here, because this file never runs again on an
-- existing volume. Migrations run after dbinit; cmd/seed fills in an org.
-- Reset with: docker compose -f deploy/docker-compose.yml down -v

CREATE EXTENSION IF NOT EXISTS pgcrypto;
