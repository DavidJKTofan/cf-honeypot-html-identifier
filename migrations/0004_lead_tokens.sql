-- Beacon evidence on leads.
--
-- 1. leads.token: the full sealed token a beacon reported (only our key opens it). An
--    investigation uses it when its own capture finds no token, which is what a clone
--    that cloaks the investigator, or entity-encodes the token, looks like. It is the
--    scraper's token, never anything about the clone's visitor.
-- 2. leads.token_ip: the scraper IP that token names. A beacon whose token names a
--    different IP on an already-approved host re-opens the lead (a re-scrape), instead
--    of being absorbed as one more hit.
-- 3. leads.reopened_at: when the lead was last re-opened (cooldown against re-notifying).
ALTER TABLE leads ADD COLUMN token TEXT;
ALTER TABLE leads ADD COLUMN token_ip TEXT;
ALTER TABLE leads ADD COLUMN reopened_at INTEGER;
