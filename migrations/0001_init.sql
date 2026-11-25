-- cf-honeypot-html-identifier: small, bounded tables only.
-- Per-request data lives inside the sealed token and in Workers Analytics Engine,
-- never here. Rows are created only by deduplicated, rate-limited honeypot events
-- (trap hits, beacons, hotlinks, Brand Protection matches) and by admin actions.

-- Flags: who gets a decoy (Worker) or a block (WAF IP List). Nothing is enforced
-- until a human approves it (status = 'active').
CREATE TABLE IF NOT EXISTS flags (
  indicator    TEXT PRIMARY KEY,                         -- 'ip:203.0.113.7' | 'ja4:t13d...'
  kind         TEXT NOT NULL CHECK (kind IN ('ip', 'ja4')),
  action       TEXT NOT NULL CHECK (action IN ('decoy', 'block')),
  status       TEXT NOT NULL CHECK (status IN ('pending', 'active', 'rejected')),
  reason       TEXT,
  source       TEXT NOT NULL CHECK (source IN ('trap', 'case', 'manual')),
  source_ref   TEXT,                                     -- Ray ID or case id
  created_at   INTEGER NOT NULL,                         -- unix seconds
  updated_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  hits         INTEGER NOT NULL DEFAULT 1,
  list_item_id TEXT                                      -- WAF list item id when action = 'block'
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_flags_status_expires ON flags (status, expires_at);

-- Leads: foreign hosts that may be running a copy of the site. Pending until approved.
CREATE TABLE IF NOT EXISTS leads (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  host       TEXT NOT NULL UNIQUE,
  sample_url TEXT,
  source     TEXT NOT NULL CHECK (source IN ('beacon', 'referer', 'brand_protection', 'manual')),
  token_ray  TEXT,                                       -- Ray ID decoded from a beacon token
  status     TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'dismissed')),
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  hits       INTEGER NOT NULL DEFAULT 1,
  case_id    TEXT
);
CREATE INDEX IF NOT EXISTS idx_leads_status ON leads (status, last_seen);

-- Cases: one InvestigateWorkflow instance each (id = workflow instance id).
CREATE TABLE IF NOT EXISTS cases (
  id          TEXT PRIMARY KEY,
  lead_id     INTEGER,
  url         TEXT NOT NULL,
  host        TEXT NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('collecting', 'awaiting_decision', 'applying', 'closed', 'no_evidence', 'expired', 'errored')),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  token_count INTEGER NOT NULL DEFAULT 0,
  report_key  TEXT,                                      -- R2 key of report.json
  decision    TEXT                                       -- JSON of the applied decision
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status, updated_at);

-- Tokens decoded from a case's captured page (who fetched the copied HTML).
CREATE TABLE IF NOT EXISTS case_tokens (
  case_id   TEXT NOT NULL,
  ray_id    TEXT NOT NULL,
  ip        TEXT NOT NULL,
  asn       INTEGER,
  country   TEXT,
  issued_at INTEGER NOT NULL,
  carrier   TEXT,
  PRIMARY KEY (case_id, ray_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_case_tokens_ip ON case_tokens (ip);
