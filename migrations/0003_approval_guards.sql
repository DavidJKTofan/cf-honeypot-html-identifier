-- Approval guards: let the database, not only application checks, enforce
-- "at most one open investigation per host", and index the daily flag purge.

-- 1. Neutralise duplicate open cases that concurrent approvals may already have
--    created, so the unique index below can be built on live data. The newest open
--    case per host stays open; older duplicates become 'errored'.
UPDATE cases
SET status = 'errored', updated_at = CAST(strftime('%s', 'now') AS INTEGER)
WHERE status IN ('collecting', 'awaiting_decision', 'applying')
  AND EXISTS (
    SELECT 1 FROM cases AS newer
    WHERE newer.host = cases.host
      AND newer.status IN ('collecting', 'awaiting_decision', 'applying')
      AND (newer.created_at > cases.created_at OR (newer.created_at = cases.created_at AND newer.id > cases.id))
  );

-- 2. One open case per host. A second INSERT for the same host fails with
--    "UNIQUE constraint failed", which startInvestigation reports as a refusal.
--    Closed, expired, errored and no_evidence cases don't count.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_open_host
  ON cases (host)
  WHERE status IN ('collecting', 'awaiting_decision', 'applying');

-- 3. The daily purge filters on expires_at alone, which idx_flags_status_expires
--    (status first) can't serve.
CREATE INDEX IF NOT EXISTS idx_flags_expires ON flags (expires_at);

-- Refresh query planner statistics after the schema change.
-- https://developers.cloudflare.com/d1/sql-api/sql-statements/#pragma-optimize
PRAGMA optimize;
