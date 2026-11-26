/**
 * The pending trap-flag digest (daily from MaintenanceWorkflow, or on demand from
 * POST /notify/flags): the most active pending flags, each annotated with an open case
 * that already covers its IP, so approvers don't decide the same IP twice.
 */
import type { FlagNotice } from "../notify";
import { openCasesForIps, parseIndicator, topPendingFlags } from "../storage/d1";

export interface FlagDigest {
	flags: FlagNotice[];
	/** All pending flags (the digest shows the top `limit`). */
	total: number;
	/** Shown flags whose IP is part of an open case. */
	inOpenCase: number;
}

export async function pendingFlagDigest(db: D1Database, limit = 5): Promise<FlagDigest> {
	const { flags, total } = await topPendingFlags(db, limit);
	const ipOf = (indicator: string) => {
		const p = parseIndicator(indicator);
		return p?.kind === "ip" ? p.value : null;
	};
	const ips = flags.map((f) => ipOf(f.indicator)).filter((ip): ip is string => ip !== null);
	const open = new Map<string, { id: string; status: string }>();
	// Newest case first: keep the first (newest) per IP.
	for (const c of await openCasesForIps(db, ips)) if (!open.has(c.ip)) open.set(c.ip, { id: c.case_id, status: c.status });
	const notices = flags.map((f): FlagNotice => {
		const ip = ipOf(f.indicator);
		const openCase = ip ? open.get(ip) : undefined;
		return { indicator: f.indicator, reason: f.reason, hits: f.hits, createdAt: f.created_at, ...(openCase ? { openCase } : {}) };
	});
	return { flags: notices, total, inOpenCase: notices.filter((n) => n.openCase).length };
}
