/**
 * D1 access. Hot path = one indexed read through the Sessions API, so it can be
 * served by the nearest read replica. All writes are bounded (dedup + rate limits).
 * https://developers.cloudflare.com/d1/best-practices/read-replication/
 */
import { errorMessage, log, nowSec } from "../core/util";

export type FlagKind = "ip" | "ja4";
export type FlagAction = "decoy" | "block";
export type FlagStatus = "pending" | "active" | "rejected";
export type FlagSource = "trap" | "case" | "manual";

export interface FlagRow {
	indicator: string;
	kind: FlagKind;
	action: FlagAction;
	status: FlagStatus;
	reason: string | null;
	source: FlagSource;
	source_ref: string | null;
	created_at: number;
	updated_at: number;
	expires_at: number;
	hits: number;
	/** Legacy column (0001), unused: WAF list items are looked up by IP when they are removed. */
	list_item_id: string | null;
}

export type LeadSource = "beacon" | "referer" | "brand_protection" | "manual";
export type LeadStatus = "pending" | "approved" | "dismissed";

export interface LeadRow {
	id: number;
	host: string;
	sample_url: string | null;
	source: LeadSource;
	token_ray: string | null;
	status: LeadStatus;
	first_seen: number;
	last_seen: number;
	hits: number;
	case_id: string | null;
	notify_ref: string | null;
	/** Full sealed token a beacon reported (0004). Evidence when the investigator's capture finds none. */
	token: string | null;
	/** Scraper IP named by `token` (0004). A beacon naming another IP re-opens an approved lead. */
	token_ip: string | null;
	/** When the lead was last re-opened by a re-scrape (0004). */
	reopened_at: number | null;
}

/** A re-scraped host is re-opened (and notified) at most once per this many seconds. */
export const LEAD_REOPEN_COOLDOWN_SEC = 86_400;

export type CaseStatus =
	| "collecting"
	| "awaiting_decision"
	| "applying"
	| "closed"
	| "no_evidence"
	| "expired"
	| "errored";

export interface CaseRow {
	id: string;
	lead_id: number | null;
	url: string;
	host: string;
	status: CaseStatus;
	created_at: number;
	updated_at: number;
	token_count: number;
	report_key: string | null;
	decision: string | null;
	notify_ref: string | null;
	hosted_on_cloudflare: number | null;
	abuse_report: string | null;
	decided_by: string | null;
}

export interface CaseTokenRow {
	case_id: string;
	ray_id: string;
	ip: string;
	asn: number | null;
	country: string | null;
	issued_at: number;
	carrier: string | null;
}

const DAY = 86_400;

export function indicatorFor(kind: FlagKind, value: string): string {
	return `${kind}:${value.trim().toLowerCase()}`;
}

export function parseIndicator(indicator: string): { kind: FlagKind; value: string } | null {
	const m = /^(ip|ja4):(.+)$/.exec(indicator.trim());
	return m ? { kind: m[1] as FlagKind, value: m[2] ?? "" } : null;
}

// ---------------------------------------------------------------- flags

/** Hot path: is any of these indicators actively flagged? Fails open (null). */
export async function activeFlagAction(db: D1Database, indicators: string[]): Promise<FlagAction | null> {
	if (indicators.length === 0) return null;
	try {
		const session = db.withSession("first-unconstrained");
		const placeholders = indicators.map(() => "?").join(",");
		const row = await session
			.prepare(
				`SELECT action FROM flags
				 WHERE indicator IN (${placeholders}) AND status = 'active' AND expires_at > ?
				 ORDER BY CASE action WHEN 'block' THEN 0 ELSE 1 END
				 LIMIT 1`,
			)
			.bind(...indicators, nowSec())
			.first<{ action: FlagAction }>();
		return row?.action ?? null;
	} catch (err) {
		log("error", "flag lookup failed (failing open)", { error: errorMessage(err) });
		return null;
	}
}

/** Trap hit: record a PENDING decoy flag (no enforcement until approved). */
export async function recordPendingFlag(
	db: D1Database,
	f: { kind: FlagKind; value: string; reason: string; sourceRef: string; pendingTtlDays: number },
): Promise<void> {
	const now = nowSec();
	await db
		.prepare(
			`INSERT INTO flags (indicator, kind, action, status, reason, source, source_ref, created_at, updated_at, expires_at, hits)
			 VALUES (?, ?, 'decoy', 'pending', ?, 'trap', ?, ?, ?, ?, 1)
			 ON CONFLICT (indicator) DO UPDATE SET hits = flags.hits + 1, updated_at = excluded.updated_at`,
		)
		.bind(indicatorFor(f.kind, f.value), f.kind, f.reason, f.sourceRef, now, now, now + f.pendingTtlDays * DAY)
		.run();
}

/**
 * Human-approved flag (manual or case decision): active immediately. When it replaces a
 * row from another source (say a trap flag that a case decision now covers), the old
 * provenance is kept in `reason` as "(previously trap <ray>: …)" instead of being lost.
 */
export async function upsertActiveFlag(
	db: D1Database,
	f: { kind: FlagKind; value: string; action: FlagAction; reason: string; source: FlagSource; sourceRef: string | null; ttlDays: number },
): Promise<FlagRow> {
	const now = nowSec();
	const indicator = indicatorFor(f.kind, f.value);
	const row = await db
		.prepare(
			`INSERT INTO flags (indicator, kind, action, status, reason, source, source_ref, created_at, updated_at, expires_at, hits)
			 VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, 1)
			 ON CONFLICT (indicator) DO UPDATE SET action = excluded.action, status = 'active',
			   reason = substr(excluded.reason ||
			     CASE WHEN flags.source <> excluded.source OR COALESCE(flags.source_ref, '') <> COALESCE(excluded.source_ref, '')
			       THEN ' (previously ' || flags.source || COALESCE(' ' || flags.source_ref, '') || ': ' || COALESCE(flags.reason, '') || ')'
			       ELSE '' END, 1, 500),
			   source = excluded.source, source_ref = excluded.source_ref, updated_at = excluded.updated_at, expires_at = excluded.expires_at
			 RETURNING *`,
		)
		.bind(indicator, f.kind, f.action, f.reason, f.source, f.sourceRef, now, now, now + f.ttlDays * DAY)
		.first<FlagRow>();
	if (!row) throw new Error(`flag ${indicator} not returned by upsert`);
	return row;
}

export async function getFlag(db: D1Database, indicator: string): Promise<FlagRow | null> {
	return db.prepare(`SELECT * FROM flags WHERE indicator = ?`).bind(indicator).first<FlagRow>();
}

/** Pending flags for the approval digest, most active first. */
export async function topPendingFlags(db: D1Database, limit: number): Promise<{ flags: FlagRow[]; total: number }> {
	const [rows, count] = await Promise.all([
		db.prepare(`SELECT * FROM flags WHERE status = 'pending' ORDER BY hits DESC, updated_at DESC LIMIT ?`).bind(limit).all<FlagRow>(),
		db.prepare(`SELECT COUNT(*) AS n FROM flags WHERE status = 'pending'`).first<{ n: number }>(),
	]);
	return { flags: rows.results, total: count?.n ?? 0 };
}

export async function listFlags(db: D1Database, status: FlagStatus | null, limit = 100): Promise<FlagRow[]> {
	const stmt = status
		? db.prepare(`SELECT * FROM flags WHERE status = ? ORDER BY updated_at DESC LIMIT ?`).bind(status, limit)
		: db.prepare(`SELECT * FROM flags ORDER BY updated_at DESC LIMIT ?`).bind(limit);
	return (await stmt.all<FlagRow>()).results;
}

/** Statements per `db.batch()` call. A batch is one transaction and counts as one query per invocation. */
const BATCH_CHUNK = 100;

function chunked<T>(items: readonly T[], size = BATCH_CHUNK): T[][] {
	const out: T[][] = [];
	for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
	return out;
}

/**
 * Approve pending flags (optionally switching decoy → block). Returns approved rows.
 * One `db.batch()` per 100 indicators instead of one round trip each; only rows that
 * were still `pending` change (so a concurrent approve/reject can't be undone).
 */
export async function approveFlags(
	db: D1Database,
	indicators: string[],
	opts: { ttlDays: number; action?: FlagAction },
): Promise<FlagRow[]> {
	if (indicators.length === 0) return [];
	const now = nowSec();
	const stmt = db.prepare(
		`UPDATE flags SET status = 'active', action = COALESCE(?, action), updated_at = ?, expires_at = ?
		 WHERE indicator = ? AND status = 'pending' RETURNING *`,
	);
	const approved: FlagRow[] = [];
	for (const chunk of chunked(indicators)) {
		const results = await db.batch<FlagRow>(chunk.map((i) => stmt.bind(opts.action ?? null, now, now + opts.ttlDays * DAY, i)));
		for (const r of results) approved.push(...r.results);
	}
	return approved;
}

/** Reject pending flags in batches. Returns how many rows changed. */
export async function rejectFlags(db: D1Database, indicators: string[]): Promise<number> {
	if (indicators.length === 0) return 0;
	const now = nowSec();
	const stmt = db.prepare(`UPDATE flags SET status = 'rejected', updated_at = ? WHERE indicator = ? AND status = 'pending'`);
	let n = 0;
	for (const chunk of chunked(indicators)) {
		const results = await db.batch(chunk.map((i) => stmt.bind(now, i)));
		for (const r of results) n += r.meta.changes ?? 0;
	}
	return n;
}

export async function deleteFlag(db: D1Database, indicator: string): Promise<FlagRow | null> {
	return db.prepare(`DELETE FROM flags WHERE indicator = ? RETURNING *`).bind(indicator).first<FlagRow>();
}

export type ExpiredFlag = Pick<FlagRow, "indicator" | "kind" | "action" | "status">;

/**
 * Expired flags (active ones past their TTL, stale pending/rejected ones), oldest first.
 * Read-only: the maintenance Workflow removes the WAF list items of expired active
 * blocks first, and only then deletes the rows (`deleteExpiredFlags`).
 */
export async function listExpiredFlags(db: D1Database, now: number, limit = 1000): Promise<ExpiredFlag[]> {
	const { results } = await db
		.prepare(`SELECT indicator, kind, action, status FROM flags WHERE expires_at <= ? ORDER BY expires_at ASC LIMIT ?`)
		.bind(now, limit)
		.all<ExpiredFlag>();
	return results;
}

/**
 * Delete these flags if they are still expired at `now` (a flag re-approved in the
 * meantime has a new `expires_at` and is kept). Returns the number of deleted rows.
 */
export async function deleteExpiredFlags(db: D1Database, indicators: string[], now: number): Promise<number> {
	let deleted = 0;
	const stmt = db.prepare(`DELETE FROM flags WHERE indicator = ? AND expires_at <= ?`);
	for (let i = 0; i < indicators.length; i += 100) {
		const results = await db.batch(indicators.slice(i, i + 100).map((ind) => stmt.bind(ind, now)));
		for (const r of results) deleted += r.meta.changes ?? 0;
	}
	return deleted;
}

export type BlockFlag = Pick<FlagRow, "indicator" | "kind" | "action" | "reason" | "source" | "source_ref">;

/** Active, unexpired IP block flags: what the WAF list should contain (read-only, bounded). */
export async function activeBlockFlags(db: D1Database, now: number, limit = 10_000): Promise<BlockFlag[]> {
	const { results } = await db
		.prepare(
			`SELECT indicator, kind, action, reason, source, source_ref FROM flags
			 WHERE status = 'active' AND action = 'block' AND kind = 'ip' AND expires_at > ? LIMIT ?`,
		)
		.bind(now, limit)
		.all<BlockFlag>();
	return results;
}

// ---------------------------------------------------------------- leads

/**
 * Insert or bump a lead. `isNew` is true only on first sight (used to notify once).
 * The token is stored on insert only: a later beacon attaches it to a lead that has none
 * with `attachLeadToken`, an atomic claim, so exactly one caller learns it was the first.
 */
export interface LeadInput {
	host: string;
	sampleUrl: string | null;
	source: LeadSource;
	tokenRay: string | null;
	/** Full sealed token (beacon leads only; already validated by the beacon handler). */
	token?: string | null;
	/** Scraper IP the token names (beacon leads only). */
	tokenIp?: string | null;
}

export async function upsertLead(db: D1Database, l: LeadInput): Promise<{ lead: LeadRow; isNew: boolean } | null> {
	const now = nowSec();
	const lead = await db
		.prepare(
			`INSERT INTO leads (host, sample_url, source, token_ray, token, token_ip, status, first_seen, last_seen, hits)
			 VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, 1)
			 ON CONFLICT (host) DO UPDATE SET last_seen = excluded.last_seen, hits = leads.hits + 1,
			   sample_url = COALESCE(leads.sample_url, excluded.sample_url)
			 RETURNING *`,
		)
		.bind(l.host.toLowerCase(), l.sampleUrl, l.source, l.tokenRay, l.token ?? null, l.tokenIp ?? null, now, now)
		.first<LeadRow>();
	return lead ? { lead, isNew: lead.hits === 1 } : null;
}

/**
 * Attach a beacon token to a lead that has none yet. Atomic, like every approval claim:
 * `WHERE token IS NULL` lets exactly one of several concurrent beacons win, and the
 * returned row shows the lead's status and source at that moment. Returns null when the
 * lead already had a token (another beacon got there first) or no longer exists.
 */
export async function attachLeadToken(db: D1Database, id: number, t: { token: string; tokenRay: string; tokenIp: string | null }): Promise<LeadRow | null> {
	return db
		.prepare(`UPDATE leads SET token = ?, token_ray = ?, token_ip = ? WHERE id = ? AND token IS NULL RETURNING *`)
		.bind(t.token, t.tokenRay, t.tokenIp, id)
		.first<LeadRow>();
}

/**
 * Re-open an approved lead because a beacon token names a NEW scraper IP (a re-scrape onto
 * a host that was already investigated). Atomic, like every approval claim: only an
 * `approved` lead with no open case for its host, not re-opened within the cooldown, moves
 * back to `pending`, with the new token as its evidence. Returns the row, or null if
 * nothing changed. Dismissed leads are never re-opened (a human said "ignore this host").
 */
export async function reopenLead(
	db: D1Database,
	id: number,
	t: { token: string; tokenRay: string; tokenIp: string; sampleUrl: string | null },
	cooldownSec = LEAD_REOPEN_COOLDOWN_SEC,
): Promise<LeadRow | null> {
	const now = nowSec();
	return db
		.prepare(
			`UPDATE leads SET status = 'pending', case_id = NULL, notify_ref = NULL, reopened_at = ?,
			   token = ?, token_ray = ?, token_ip = ?, sample_url = COALESCE(?, sample_url)
			 WHERE id = ? AND status = 'approved' AND token_ip IS NOT NULL AND token_ip <> ?
			   AND (reopened_at IS NULL OR reopened_at <= ?)
			   AND NOT EXISTS (SELECT 1 FROM cases WHERE cases.host = leads.host AND cases.status IN ('collecting', 'awaiting_decision', 'applying'))
			 RETURNING *`,
		)
		.bind(now, t.token, t.tokenRay, t.tokenIp, t.sampleUrl, id, t.tokenIp, now - cooldownSec)
		.first<LeadRow>();
}

export async function setLeadNotifyRef(db: D1Database, id: number, ref: string | null): Promise<void> {
	await db.prepare(`UPDATE leads SET notify_ref = ? WHERE id = ?`).bind(ref, id).run();
}

export async function listLeads(db: D1Database, status: LeadStatus | null, limit = 100): Promise<LeadRow[]> {
	const stmt = status
		? db.prepare(`SELECT * FROM leads WHERE status = ? ORDER BY last_seen DESC LIMIT ?`).bind(status, limit)
		: db.prepare(`SELECT * FROM leads ORDER BY last_seen DESC LIMIT ?`).bind(limit);
	return (await stmt.all<LeadRow>()).results;
}

export async function getLead(db: D1Database, id: number): Promise<LeadRow | null> {
	return db.prepare(`SELECT * FROM leads WHERE id = ?`).bind(id).first<LeadRow>();
}

export async function setLeadStatus(db: D1Database, id: number, status: LeadStatus, caseId?: string): Promise<void> {
	await db
		.prepare(`UPDATE leads SET status = ?, case_id = COALESCE(?, case_id) WHERE id = ?`)
		.bind(status, caseId ?? null, id)
		.run();
}

/**
 * Atomically move a lead from `pending` to `approved`. Returns false when another
 * approver (or a dismiss) got there first, so only one caller starts an investigation.
 */
export async function claimLead(db: D1Database, id: number): Promise<boolean> {
	const r = await db.prepare(`UPDATE leads SET status = 'approved' WHERE id = ? AND status = 'pending'`).bind(id).run();
	return (r.meta.changes ?? 0) === 1;
}

/** Undo `claimLead` after a failed start: back to `pending`, case link cleared. */
export async function releaseLead(db: D1Database, id: number): Promise<void> {
	await db.prepare(`UPDATE leads SET status = 'pending', case_id = NULL WHERE id = ? AND status = 'approved'`).bind(id).run();
}

/** Atomically dismiss a pending lead. Returns false if it was no longer pending. */
export async function dismissPendingLead(db: D1Database, id: number): Promise<boolean> {
	const r = await db.prepare(`UPDATE leads SET status = 'dismissed' WHERE id = ? AND status = 'pending'`).bind(id).run();
	return (r.meta.changes ?? 0) === 1;
}

export async function purgeStaleLeads(db: D1Database, pendingTtlDays: number): Promise<number> {
	const r = await db
		.prepare(`DELETE FROM leads WHERE status IN ('pending', 'dismissed') AND last_seen <= ?`)
		.bind(nowSec() - pendingTtlDays * DAY)
		.run();
	return r.meta.changes ?? 0;
}

// ---------------------------------------------------------------- cases

export async function createCase(
	db: D1Database,
	c: { id: string; leadId: number | null; url: string; host: string },
): Promise<void> {
	const now = nowSec();
	await db
		.prepare(
			`INSERT INTO cases (id, lead_id, url, host, status, created_at, updated_at)
			 VALUES (?, ?, ?, ?, 'collecting', ?, ?) ON CONFLICT (id) DO NOTHING`,
		)
		.bind(c.id, c.leadId, c.url, c.host.toLowerCase(), now, now)
		.run();
}

/** Columns `updateCase` may set. Checked at runtime: column names can't be bound as parameters. */
const CASE_UPDATABLE = new Set([
	"status",
	"token_count",
	"report_key",
	"decision",
	"notify_ref",
	"hosted_on_cloudflare",
	"abuse_report",
	"decided_by",
] as const);
type CaseUpdatable = typeof CASE_UPDATABLE extends Set<infer K> ? K : never;

export async function updateCase(db: D1Database, id: string, fields: Partial<Pick<CaseRow, CaseUpdatable>>): Promise<void> {
	const sets: string[] = ["updated_at = ?"];
	const values: (string | number | null)[] = [nowSec()];
	for (const [k, v] of Object.entries(fields)) {
		if (!CASE_UPDATABLE.has(k as CaseUpdatable)) throw new Error(`updateCase: column "${k}" is not updatable`);
		if (v === undefined) continue;
		sets.push(`${k} = ?`);
		values.push(v as string | number | null);
	}
	await db
		.prepare(`UPDATE cases SET ${sets.join(", ")} WHERE id = ?`)
		.bind(...values, id)
		.run();
}

export async function getCase(db: D1Database, id: string): Promise<CaseRow | null> {
	return db.prepare(`SELECT * FROM cases WHERE id = ?`).bind(id).first<CaseRow>();
}

/** An open (not yet closed) case for this host, if any: prevents duplicate Workflows. */
export async function openCaseForHost(db: D1Database, host: string): Promise<CaseRow | null> {
	return db
		.prepare(`SELECT * FROM cases WHERE host = ? AND status IN ('collecting', 'awaiting_decision', 'applying') LIMIT 1`)
		.bind(host.toLowerCase())
		.first<CaseRow>();
}

/** True when a D1 error is a UNIQUE constraint violation (e.g. a second open case for a host). */
export function isUniqueViolation(err: unknown): boolean {
	return /UNIQUE constraint failed/i.test(errorMessage(err));
}

/**
 * Atomically claim a case for a decision: `awaiting_decision` → `applying`, recording
 * who decided. Returns false if another approver (or the expiry) got there first.
 */
export async function claimCaseDecision(db: D1Database, id: string, actorId: string): Promise<boolean> {
	const r = await db
		.prepare(`UPDATE cases SET status = 'applying', decided_by = ?, updated_at = ? WHERE id = ? AND status = 'awaiting_decision'`)
		.bind(actorId, nowSec(), id)
		.run();
	return (r.meta.changes ?? 0) === 1;
}

/** Undo `claimCaseDecision` when the decision event could not be delivered. */
export async function releaseCaseDecision(db: D1Database, id: string, actorId: string): Promise<void> {
	await db
		.prepare(
			`UPDATE cases SET status = 'awaiting_decision', decided_by = NULL, updated_at = ?
			 WHERE id = ? AND status = 'applying' AND decided_by = ?`,
		)
		.bind(nowSec(), id, actorId)
		.run();
}

/**
 * Atomically reserve the abuse-report slot of a case (`abuse_report IS NULL` → `marker`),
 * so two clicks can never submit the same report twice.
 */
export async function claimAbuseReport(db: D1Database, id: string, marker: string): Promise<boolean> {
	const r = await db
		.prepare(`UPDATE cases SET abuse_report = ?, updated_at = ? WHERE id = ? AND abuse_report IS NULL`)
		.bind(marker, nowSec(), id)
		.run();
	return (r.meta.changes ?? 0) === 1;
}

/** Undo `claimAbuseReport` after a failed submission (only if our marker is still there). */
export async function releaseAbuseReport(db: D1Database, id: string, marker: string): Promise<void> {
	await db
		.prepare(`UPDATE cases SET abuse_report = NULL, updated_at = ? WHERE id = ? AND abuse_report = ?`)
		.bind(nowSec(), id, marker)
		.run();
}

export async function listCases(db: D1Database, limit = 50): Promise<CaseRow[]> {
	return (await db.prepare(`SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?`).bind(limit).all<CaseRow>()).results;
}

export async function insertCaseTokens(db: D1Database, rows: CaseTokenRow[]): Promise<void> {
	if (rows.length === 0) return;
	const stmt = db.prepare(
		`INSERT INTO case_tokens (case_id, ray_id, ip, asn, country, issued_at, carrier)
		 VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (case_id, ray_id) DO NOTHING`,
	);
	await db.batch(rows.map((r) => stmt.bind(r.case_id, r.ray_id, r.ip, r.asn, r.country, r.issued_at, r.carrier)));
}

export async function getCaseTokens(db: D1Database, caseId: string): Promise<CaseTokenRow[]> {
	return (
		await db.prepare(`SELECT * FROM case_tokens WHERE case_id = ? ORDER BY issued_at ASC`).bind(caseId).all<CaseTokenRow>()
	).results;
}
