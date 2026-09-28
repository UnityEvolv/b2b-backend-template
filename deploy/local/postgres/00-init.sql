-- Runs once, when the local Postgres volume is created.
--
-- Deliberately almost empty. Schemas and roles per service are made by dbinit
-- on every start (UO-35), not here, because this file never runs again on an
-- existing volume. Migrations arrive with UO-36, the seeded org with UO-203.
-- Reset with: docker compose -f deploy/docker-compose.yml down -v

CREATE EXTENSION IF NOT EXISTS pgcrypto;
