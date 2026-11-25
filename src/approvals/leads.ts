/**
 * Lead intake: record (deduplicated by host) and, on first sight only, ask a
 * human via the configured notifier. Leads never start Workflows by themselves.
 *
 * Re-scrapes: once a host's lead is approved (investigated), further beacons only add
 * hits. If a beacon's token names a DIFFERENT scraper IP, the scraper fetched a fresh
 * copy from somewhere else, so the lead is re-opened (back to `pending`, notified again)
 * at most once per LEAD_REOPEN_COOLDOWN_SEC. Dismissed leads stay dismissed.
 */
import type { Config } from "../core/config";
import { notifySafe } from "../notify";
import { reopenLead, setLeadNotifyRef, upsertLead, type LeadInput, type LeadRow } from "../storage/d1";

async function notifyLead(env: Env, cfg: Config, lead: LeadRow, reopened: boolean): Promise<void> {
	const ref = await notifySafe(env, cfg, "lead", (n) =>
		n.notifyLead({
			id: lead.id,
			host: lead.host,
			source: lead.source,
			sampleUrl: lead.sample_url,
			tokenRay: lead.token_ray,
			firstSeen: lead.first_seen,
			hits: lead.hits,
			reopened,
		}),
	);
	if (ref) await setLeadNotifyRef(env.DB, lead.id, ref);
}

export async function recordLead(env: Env, cfg: Config, l: LeadInput): Promise<{ lead: LeadRow; isNew: boolean; reopened: boolean } | null> {
	const r = await upsertLead(env.DB, l);
	if (!r) return null;
	if (r.isNew && r.lead.status === "pending") {
		await notifyLead(env, cfg, r.lead, false);
		return { ...r, reopened: false };
	}
	const prev = r.lead;
	if (prev.status === "approved" && l.token && l.tokenRay && l.tokenIp && prev.token_ip && prev.token_ip !== l.tokenIp) {
		const reopened = await reopenLead(env.DB, prev.id, { token: l.token, tokenRay: l.tokenRay, tokenIp: l.tokenIp, sampleUrl: l.sampleUrl });
		if (reopened) {
			await notifyLead(env, cfg, reopened, true);
			return { lead: reopened, isNew: false, reopened: true };
		}
	}
	return { ...r, reopened: false };
}
