/**
 * Enforcement, only ever called after explicit human approval:
 * - decoy → active D1 flag, served by this Worker
 * - block → active D1 flag + WAF IP List item (blocked at the edge, before the Worker)
 *
 * Cloudflare IP ranges are protected: they are never flagged or listed.
 *
 * WAF List writes are asynchronous bulk operations. Every write here waits (briefly)
 * for its operation to finish so the outcome is reported honestly, and the daily
 * maintenance `reconcileWafList` is the safety net for anything that still drifts.
 * https://developers.cloudflare.com/waf/tools/lists/lists-api/endpoints/
 */
import type { Config } from "../core/config";
import { errorMessage, log, nowSec } from "../core/util";
import { canonicalIp } from "../identity/token";
import { cfApi, type CfApi, type CfApiOptions } from "../integrations/cloudflare/api";
import { isCloudflareIp, loadCloudflareRanges, type CloudflareRanges } from "../integrations/cloudflare/ip-ranges";
import {
	ACTIVE_BLOCK_FLAGS_LIMIT,
	activeBlockFlags,
	deleteFlag,
	getFlag,
	parseIndicator,
	upsertActiveFlag,
	type BlockFlag,
	type FlagAction,
	type FlagKind,
	type FlagRow,
	type FlagSource,
	type UpsertedFlag,
} from "../storage/d1";

/**
 * Outcome of a WAF list sync:
 * - `added` / `removed`: the bulk operation completed
 * - `pending`: accepted but still queued when the wait budget ran out (not known to have failed)
 * - `absent`: nothing to remove (the IPs were not in the list)
 * - `skipped`: no CF_API_TOKEN / WAF_LIST_ID configured
 * - `not_applicable`: nothing to sync (no block flags for IPs)
 * - `error`: the API call or the bulk operation failed
 */
export type WafSync = "added" | "removed" | "pending" | "absent" | "skipped" | "not_applicable" | "error";

/** Comment prefix of every list item this Worker creates. Reconcile only ever touches these. */
export const WAF_COMMENT_PREFIX = "cf-honeypot:";

/**
 * Request-path defaults: the admin API and a Discord click's `waitUntil` have about 30 s in
 * total, so one sync stays under ~16 s (8 s of API retries plus 8 s of polling).
 */
const REQUEST_PATH = { pollBudgetMs: 8_000, retryBudgetMs: 8_000, timeoutMs: 8_000 } as const satisfies CfApiOptions & { pollBudgetMs: number };

export interface WafOptions {
	/** Client to use (tests inject one); `null` = not configured. Defaults to `cfApi(env, …)`. */
	api?: CfApi | null;
	/** How long to poll the bulk operation (default 8 s; Workflow steps pass more). */
	pollBudgetMs?: number;
	/** Retry budget per API call (default 8 s). */
	retryBudgetMs?: number;
	/** Throw instead of returning `"error"`, so a Workflow step's retries apply. */
	throwOnError?: boolean;
}

/** Thrown when someone tries to flag a Cloudflare IP. */
export class ProtectedIpError extends Error {
	constructor(readonly ip: string) {
		super(`${ip} is a Cloudflare IP: never flagged or blocked (use an abuse report instead)`);
	}
}

/** Thrown for a malformed indicator value (not a single IP, CIDR ranges included, or not a JA4). */
export class InvalidIndicatorError extends Error {}

/** Raised by WAF helpers with `throwOnError` when the API call or bulk operation fails. */
export class WafSyncError extends Error {}

const JA4 = /^[a-z0-9_]{1,64}$/;

/**
 * Validate and normalise an indicator value: a single IP in canonical form (never a
 * CIDR range: a range could cover Cloudflare or half the internet), or a JA4 string.
 */
export function normalizeIndicatorValue(kind: FlagKind, value: string): string {
	if (kind === "ip") {
		const ip = canonicalIp(value);
		if (!ip) throw new InvalidIndicatorError(`"${value.slice(0, 64)}" is not a single IPv4 or IPv6 address (ranges are not accepted)`);
		return ip;
	}
	const ja4 = value.trim().toLowerCase();
	if (!JA4.test(ja4)) throw new InvalidIndicatorError("ja4 must be 1-64 characters of a-z, 0-9 and _");
	return ja4;
}

export async function isProtectedIndicator(indicator: string, ranges?: CloudflareRanges): Promise<boolean> {
	const parsed = parseIndicator(indicator);
	if (parsed?.kind !== "ip") return false;
	return isCloudflareIp(parsed.value, ranges ?? (await loadCloudflareRanges()));
}

function wafComment(row: BlockFlag): string {
	return `${WAF_COMMENT_PREFIX} ${row.reason ?? row.source} (${row.source_ref ?? "n/a"})`.slice(0, 500);
}

function resolveApi(env: Env, opts: WafOptions): CfApi | null {
	if (opts.api !== undefined) return opts.api;
	return cfApi(env, { retryBudgetMs: opts.retryBudgetMs ?? REQUEST_PATH.retryBudgetMs, timeoutMs: REQUEST_PATH.timeoutMs });
}

function fail(opts: WafOptions, message: string): WafSync {
	log("error", message);
	if (opts.throwOnError) throw new WafSyncError(message);
	return "error";
}

/** Push block flags (IP kind only, never Cloudflare IPs) into the WAF list in ONE bulk operation. */
export async function syncBlocksToWaf(env: Env, cfg: Config, rows: BlockFlag[], opts: WafOptions = {}): Promise<WafSync> {
	const ranges = await loadCloudflareRanges();
	const seen = new Set<string>();
	const items: { ip: string; comment: string }[] = [];
	for (const r of rows) {
		if (r.action !== "block" || r.kind !== "ip") continue;
		const ip = canonicalIp(parseIndicator(r.indicator)?.value ?? "");
		if (!ip || seen.has(ip) || isCloudflareIp(ip, ranges)) continue;
		seen.add(ip);
		items.push({ ip, comment: wafComment(r) });
	}
	if (items.length === 0) return "not_applicable";
	const api = resolveApi(env, opts);
	if (!api || !cfg.wafListId) return "skipped";
	try {
		const opId = await api.addListItems(cfg.wafListId, items);
		const op = await api.waitForListOperation(opId, opts.pollBudgetMs ?? REQUEST_PATH.pollBudgetMs);
		if (op.status === "failed") return fail(opts, `waf list add failed: ${op.error ?? "bulk operation failed"}`);
		if (op.status === "timeout") log("warn", "waf list add still pending", { operationId: opId, items: items.length });
		return op.status === "completed" ? "added" : "pending";
	} catch (err) {
		if (err instanceof WafSyncError) throw err;
		return fail(opts, `waf list add failed: ${errorMessage(err)}`);
	}
}

export interface WafRemoval {
	status: WafSync;
	/** IPs no longer in the list (removed now, or already absent). */
	removed: string[];
	/** IPs whose lookup or removal failed: keep their D1 rows so the next run retries. */
	failed: string[];
	error?: string;
}

/**
 * Remove the WAF list items for these IPs (looked up by IP, deleted in one bulk operation).
 * Never throws: per-IP failures are reported in `failed`.
 */
export async function removeBlocksFromWafDetailed(env: Env, cfg: Config, ips: string[], opts: WafOptions = {}): Promise<WafRemoval> {
	const wanted = [...new Set(ips.map((ip) => canonicalIp(ip) ?? ip))];
	if (wanted.length === 0) return { status: "not_applicable", removed: [], failed: [] };
	const api = resolveApi(env, opts);
	if (!api || !cfg.wafListId) return { status: "skipped", removed: wanted, failed: [] };

	const found: { ip: string; id: string }[] = [];
	const absent: string[] = [];
	const failed: string[] = [];
	let error: string | undefined;
	for (const ip of wanted) {
		try {
			const item = await api.findListItem(cfg.wafListId, ip);
			if (item) found.push({ ip, id: item.id });
			else absent.push(ip);
		} catch (err) {
			failed.push(ip);
			error = errorMessage(err);
		}
	}
	if (found.length === 0) {
		return failed.length ? { status: "error", removed: absent, failed, error } : { status: "absent", removed: absent, failed: [] };
	}
	try {
		const opId = await api.deleteListItems(cfg.wafListId, found.map((f) => f.id));
		const op = opId ? await api.waitForListOperation(opId, opts.pollBudgetMs ?? REQUEST_PATH.pollBudgetMs) : { status: "completed" as const };
		if (op.status === "failed") {
			return { status: "error", removed: absent, failed: [...failed, ...found.map((f) => f.ip)], error: op.error ?? "bulk operation failed" };
		}
		if (op.status === "timeout") log("warn", "waf list delete still pending", { operationId: opId, items: found.length });
		const removed = [...absent, ...found.map((f) => f.ip)];
		if (failed.length) return { status: "error", removed, failed, error };
		return { status: op.status === "completed" ? "removed" : "pending", removed, failed: [] };
	} catch (err) {
		return { status: "error", removed: absent, failed: [...failed, ...found.map((f) => f.ip)], error: errorMessage(err) };
	}
}

/** Remove the WAF list items for these IPs. Returns `"error"` (or throws with `throwOnError`) on any failure. */
export async function removeBlocksFromWaf(env: Env, cfg: Config, ips: string[], opts: WafOptions = {}): Promise<WafSync> {
	const r = await removeBlocksFromWafDetailed(env, cfg, ips, opts);
	if (r.status === "error") return fail(opts, `waf list delete failed for ${r.failed.length} ip(s): ${r.error ?? "unknown error"}`);
	return r.status;
}

export interface ApprovedFlagInput {
	kind: FlagKind;
	value: string;
	action: FlagAction;
	reason: string;
	source: FlagSource;
	sourceRef: string | null;
	ttlDays: number;
}

/**
 * Validate, protect and store one human-approved flag WITHOUT touching the WAF list,
 * so callers can batch every block into one `syncBlocksToWaf` call (and every
 * block-to-decoy change into one `removeBlocksFromWaf` call, see `downgradedBlockIp`).
 * Throws InvalidIndicatorError or ProtectedIpError.
 */
export async function recordApprovedFlag(env: Env, f: ApprovedFlagInput, ranges?: CloudflareRanges): Promise<UpsertedFlag> {
	const value = normalizeIndicatorValue(f.kind, f.value);
	if (f.kind === "ip" && isCloudflareIp(value, ranges ?? (await loadCloudflareRanges()))) throw new ProtectedIpError(value);
	return upsertActiveFlag(env.DB, { ...f, value });
}

/**
 * The IP whose WAF list item must be removed because this approval turned an active block
 * into a decoy, or null. Without the removal the IP stays blocked at the edge (the list rule
 * runs before the Worker) until the daily reconcile.
 */
export function downgradedBlockIp(u: UpsertedFlag): string | null {
	if (u.row.kind !== "ip" || u.row.action === "block") return null;
	if (u.previous?.action !== "block" || u.previous.status !== "active") return null;
	return parseIndicator(u.row.indicator)?.value ?? null;
}

export async function applyFlag(env: Env, cfg: Config, f: ApprovedFlagInput, opts: WafOptions = {}): Promise<{ flag: FlagRow; waf: WafSync }> {
	const approved = await recordApprovedFlag(env, f);
	const flag = approved.row;
	const downgraded = downgradedBlockIp(approved);
	const waf = downgraded
		? await removeBlocksFromWaf(env, cfg, [downgraded], { ...opts, throwOnError: false })
		: await syncBlocksToWaf(env, cfg, [flag], opts);
	log("info", "flag applied", { indicator: flag.indicator, action: flag.action, source: flag.source, waf, removedBlock: downgraded !== null });
	return { flag, waf };
}

/**
 * Manual unflag. The WAF item is removed BEFORE the row is deleted; the row is deleted
 * even if that removal fails, because the person asked to unflag. A leftover list item
 * then has no active block flag, so the daily `reconcileWafList` removes it.
 */
export async function removeFlag(env: Env, cfg: Config, indicator: string, opts: WafOptions = {}): Promise<{ flag: FlagRow | null; waf: WafSync }> {
	const existing = await getFlag(env.DB, indicator);
	if (!existing) return { flag: null, waf: "not_applicable" };
	const parsed = parseIndicator(existing.indicator);
	const waf: WafSync =
		existing.action === "block" && existing.status === "active" && parsed?.kind === "ip"
			? await removeBlocksFromWaf(env, cfg, [parsed.value], { ...opts, throwOnError: false })
			: "not_applicable";
	const flag = await deleteFlag(env.DB, indicator);
	log(waf === "error" ? "warn" : "info", "flag removed", { indicator, waf, reconcile: waf === "error" ? "daily maintenance retries the list item" : null });
	return { flag: flag ?? existing, waf };
}

export interface ReconcileResult {
	status: "ok" | "skipped";
	listed: number;
	/** Pagination cap reached: some items were not examined. */
	truncated: boolean;
	/** `cf-honeypot:` items without an active, unexpired block flag. */
	removed: string[];
	/** Active block flags whose IP was missing from the list (re-added). */
	added: string[];
	waf: { remove: WafSync; add: WafSync };
}

/**
 * Safety net, run daily: make the WAF list match the active block flags in D1.
 * - removes items whose comment starts with `cf-honeypot:` and that have no active,
 *   unexpired block flag (never items without that prefix: humans add their own)
 * - re-adds active block flags whose IP is missing (a request-path sync that failed)
 * The list is read BEFORE D1, so an approval in flight (D1 write, then list add) is never
 * mistaken for an orphan. Bounded by `maxPages` × 500 items and `maxChanges` per direction.
 */
export async function reconcileWafList(
	env: Env,
	cfg: Config,
	opts: WafOptions & { maxPages?: number; maxChanges?: number; /** Cap on active block flags read from D1 (tests). */ maxFlags?: number } = {},
): Promise<ReconcileResult> {
	const empty: ReconcileResult = { status: "skipped", listed: 0, truncated: false, removed: [], added: [], waf: { remove: "skipped", add: "skipped" } };
	const api = resolveApi(env, opts);
	if (!api || !cfg.wafListId) return empty;

	const maxPages = opts.maxPages ?? 10;
	const maxChanges = opts.maxChanges ?? 500;
	const inList = new Set<string>();
	const ours: { id: string; ip: string }[] = [];
	let cursor: string | undefined;
	let pages = 0;
	let truncated = false;
	let listed = 0;
	for (;;) {
		const page = await api.listItemsPage(cfg.wafListId, cursor);
		pages++;
		for (const item of page.items) {
			listed++;
			const ip = item.ip ? (canonicalIp(item.ip) ?? item.ip) : null;
			if (!ip) continue;
			inList.add(ip);
			if (typeof item.comment === "string" && item.comment.startsWith(WAF_COMMENT_PREFIX)) ours.push({ id: item.id, ip });
		}
		if (!page.next) break;
		if (pages >= maxPages) {
			truncated = true;
			break;
		}
		cursor = page.next;
	}

	const activeFlags = new Map<string, BlockFlag>();
	const maxFlags = opts.maxFlags ?? ACTIVE_BLOCK_FLAGS_LIMIT;
	const blockRows = await activeBlockFlags(env.DB, nowSec(), maxFlags);
	for (const f of blockRows) {
		const ip = canonicalIp(parseIndicator(f.indicator)?.value ?? "");
		if (ip) activeFlags.set(ip, f);
	}
	// A capped D1 result may miss active blocks: their list items would look like orphans and be
	// deleted. Only remove orphans when the set of active blocks is known to be complete.
	const flagsComplete = blockRows.length < maxFlags;
	if (!flagsComplete) log("warn", "waf reconcile: active block flags hit the query cap; orphan removal skipped", { limit: maxFlags });
	const orphans = flagsComplete ? ours.filter((o) => !activeFlags.has(o.ip)).slice(0, maxChanges) : [];
	// With a truncated listing an IP may simply be on an unread page; re-adding is an idempotent upsert anyway.
	// syncBlocksToWaf skips Cloudflare IPs.
	const missing = [...activeFlags.entries()].filter(([ip]) => !inList.has(ip)).slice(0, maxChanges);

	const result: ReconcileResult = { status: "ok", listed, truncated, removed: [], added: [], waf: { remove: "not_applicable", add: "not_applicable" } };
	const pollBudgetMs = opts.pollBudgetMs ?? REQUEST_PATH.pollBudgetMs;

	if (orphans.length) {
		const opId = await api.deleteListItems(cfg.wafListId, orphans.map((o) => o.id));
		const op = opId ? await api.waitForListOperation(opId, pollBudgetMs) : { status: "completed" as const };
		if (op.status === "failed") throw new WafSyncError(`reconcile delete failed: ${op.error ?? "bulk operation failed"}`);
		result.removed = orphans.map((o) => o.ip);
		result.waf.remove = op.status === "completed" ? "removed" : "pending";
	}
	if (missing.length) {
		result.waf.add = await syncBlocksToWaf(
			env,
			cfg,
			missing.map(([, f]) => f),
			{ ...opts, api, throwOnError: true },
		);
		if (result.waf.add === "added" || result.waf.add === "pending") result.added = missing.map(([ip]) => ip);
	}
	log("info", "waf list reconciled", { listed, truncated, removed: result.removed.length, added: result.added.length });
	return result;
}
