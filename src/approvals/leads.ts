/**
 * Lead intake: record (deduplicated by host) and, on first sight only, ask a
 * human via the configured notifier. Leads never start Workflows by themselves.
 *
 * Corroboration: a `referer` or `brand_protection` lead is a weak signal. When a beacon
 * later reports the first valid token for that host while the lead is still `pending`,
 * the original message is updated in place (or one new message is posted when there is
 * none to edit). The token attach is an atomic claim (`WHERE token IS NULL`), so this
 * happens at most once per lead, even under concurrent beacons.
 *
 * Re-scrapes: once a host's lead is approved (investigated), further beacons only add
 * hits. If a beacon's token names a DIFFERENT scraper IP, the scraper fetched a fresh
 * copy from somewhere else, so the lead is re-opened (back to `pending`, notified again)
 * at most once per LEAD_REOPEN_COOLDOWN_SEC. Dismissed leads stay dismissed.
 */
import type { Config } from "../core/config";
import { notifySafe, updateOrPostLead, type LeadNotice } from "../notify";
import { attachLeadToken, reopenLead, setLeadNotifyRef, upsertLead, type LeadInput, type LeadRow } from "../storage/d1";

export interface RecordedLead {
	lead: LeadRow;
	isNew: boolean;
	reopened: boolean;
	/** This call brought the first beacon token for a pending non-beacon lead (notified once). */
	corroborated: boolean;
}

function leadNotice(lead: LeadRow, flags: Pick<LeadNotice, "reopened" | "corroborated" | "retryAfterCase"> = {}): LeadNotice {
	return {
		id: lead.id,
		host: lead.host,
		source: lead.source,
		sampleUrl: lead.sample_url,
		tokenRay: lead.token_ray,
		firstSeen: lead.first_seen,
		hits: lead.hits,
		...flags,
	};
}

/**
 * Post a lead to the approval channel and remember the message. Also used by the
 * InvestigateWorkflow to re-offer a lead whose investigation errored (`rateLimit: false`:
 * that is a one-off per case, not public-traffic driven).
 */
export async function notifyLead(
	env: Env,
	cfg: Config,
	lead: LeadRow,
	reopened: boolean,
	opts: { rateLimit?: boolean; retryAfterCase?: string } = {},
): Promise<void> {
	const notice = leadNotice(lead, { reopened, ...(opts.retryAfterCase ? { retryAfterCase: opts.retryAfterCase } : {}) });
	const ref = await notifySafe(env, cfg, "lead", (n) => n.notifyLead(notice), { rateLimit: opts.rateLimit !== false });
	if (ref) await setLeadNotifyRef(env.DB, lead.id, ref);
}

/**
 * Not rate-limited: the token claim (`attachLeadToken`) already allows at most one
 * corroboration per lead, and it is spent before this runs, so a skipped message here
 * would be lost for good.
 */
async function notifyCorroborated(env: Env, cfg: Config, lead: LeadRow): Promise<void> {
	const ref = await notifySafe(env, cfg, "lead-corroborated", (n) => updateOrPostLead(n, lead.notify_ref, leadNotice(lead, { corroborated: true })), {
		rateLimit: false,
	});
	if (ref && ref !== lead.notify_ref) await setLeadNotifyRef(env.DB, lead.id, ref);
}

export async function recordLead(env: Env, cfg: Config, l: LeadInput): Promise<RecordedLead | null> {
	const r = await upsertLead(env.DB, l);
	if (!r) return null;
	if (r.isNew && r.lead.status === "pending") {
		await notifyLead(env, cfg, r.lead, false);
		return { ...r, reopened: false, corroborated: false };
	}
	const prev = r.lead;

	// First token for a lead that had none (a referer or Brand Protection lead, or a row from
	// before 0004). The token is always attached, as evidence, whatever the status; only a
	// still-pending lead from a weaker source is escalated. The claim's returned row carries
	// status and source as of the claim, so a concurrent dismiss or approval is respected.
	if (l.token && l.tokenRay && !prev.token) {
		const attached = await attachLeadToken(env.DB, prev.id, { token: l.token, tokenRay: l.tokenRay, tokenIp: l.tokenIp ?? null });
		const corroborated = attached !== null && attached.status === "pending" && attached.source !== "beacon";
		if (attached && corroborated) await notifyCorroborated(env, cfg, attached);
		return { lead: attached ?? prev, isNew: false, reopened: false, corroborated };
	}

	if (prev.status === "approved" && l.token && l.tokenRay && l.tokenIp && prev.token_ip && prev.token_ip !== l.tokenIp) {
		const reopened = await reopenLead(env.DB, prev.id, { token: l.token, tokenRay: l.tokenRay, tokenIp: l.tokenIp, sampleUrl: l.sampleUrl });
		if (reopened) {
			await notifyLead(env, cfg, reopened, true);
			return { lead: reopened, isNew: false, reopened: true, corroborated: false };
		}
	}
	return { ...r, reopened: false, corroborated: false };
}
