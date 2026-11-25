-- Human-in-the-loop notifications and Cloudflare abuse reporting.

-- Channel-specific reference to the approval message (e.g. "discord:<channel>:<message>"),
-- so the message can be updated once someone acts on it.
ALTER TABLE leads ADD COLUMN notify_ref TEXT;
ALTER TABLE cases ADD COLUMN notify_ref TEXT;

-- 1 when the copy resolves only to Cloudflare IPs (proxied by / hosted on Cloudflare).
ALTER TABLE cases ADD COLUMN hosted_on_cloudflare INTEGER;

-- JSON status of a submitted Cloudflare abuse report (null = not submitted).
ALTER TABLE cases ADD COLUMN abuse_report TEXT;

-- Who decided (e.g. "discord:123456789012345678" or "admin").
ALTER TABLE cases ADD COLUMN decided_by TEXT;
