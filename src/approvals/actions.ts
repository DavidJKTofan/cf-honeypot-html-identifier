/**
 * Approval actions, shared by every human entry point (admin API / CLI,
 * Discord buttons, future Slack or Telegram adapters). Each returns a short
 * human-readable summary; none throws for expected refusals.
 */
import type { Config } from "../core/config";
import { errorMessage, log, safeUrl } from "../core/util";
import { abuseReportKey } from "../workflows/report";
import { cfApi } from "../integrations/cloudflare/api";
import { buildSubmission, parseReporter, type AbuseDraft } from "../integrations/cloudflare/abuse";
import { loadCloudflareRanges } from "../integrations/cloudflare/ip-ranges";
import {
	approveFlags,
	claimAbuseReport,
	claimCaseDecision,
	dismissPendingLead,
	getCase,
	getLead,
	rejectFlags,
	releaseAbuseReport,
	releaseCaseDecision,
	updateCase,
	type FlagAction,
} from "../storage/d1";
import { CaseInputError, sendDecision, startInvestigation, type Decision } from "./cases";
import { isProtectedIndicator, syncBlocksToWaf } from "./enforce";

export interface Actor {
	/** Stable id, e.g. "discord:123456789012345678" or "admin". */
	id: string;
	/** How to show the actor in messages, e.g. "<@123…>" or "admin API". */
	label: string;
}

export interface ActionResult {
	ok: boolean;
	summary: string;
	/** Notification to update when the action did not come from that notification. */
	notifyRef?: string | null;
	data?: Record<string, unknown>;
}

/**
 * Approve a lead: start one investigation. Concurrent clicks are safe: the lead is
 * claimed atomically inside `startInvestigation`, so only one caller starts a Workflow.
 */
export async function approveLeadAction(env: Env, cfg: Config, leadId: number, actor: Actor, url?: string): Promise<ActionResult> {
	const lead = await getLead(env.DB, leadId);
	if (!lead) return { ok: false, summary: `Lead #${leadId} not found` };
	if (lead.status !== "pending") return { ok: false, summary: `Lead #${leadId} is already ${lead.status}`, notifyRef: lead.notify_ref };
	// An override URL may pick another page, never another host: the investigation would use this
	// lead's beacon token as (unconfirmed) evidence against a site it never came from.
	if (url !== undefined && safeUrl(url)?.hostname.toLowerCase() !== lead.host) {
		return { ok: false, summary: `url must be on the lead's host ${lead.host} (start a manual case for another host)`, notifyRef: lead.notify_ref };
	}
	try {
		const started = await startInvestigation(env, cfg, { url: url ?? lead.sample_url ?? `https://${lead.host}/`, leadId });
		log("info", "lead approved", { leadId, caseId: started.caseId, actor: actor.id });
		return { ok: true, summary: `Investigation \`${started.caseId}\` started by ${actor.label}`, notifyRef: lead.notify_ref, data: started };
	} catch (err) {
		if (err instanceof CaseInputError) return { ok: false, summary: err.message, notifyRef: lead.notify_ref };
		throw err;
	}
}

export async function dismissLeadAction(env: Env, leadId: number, actor: Actor): Promise<ActionResult> {
	const lead = await getLead(env.DB, leadId);
	if (!lead) return { ok: false, summary: `Lead #${leadId} not found` };
	if (lead.status !== "pending") return { ok: false, summary: `Lead #${leadId} is already ${lead.status}`, notifyRef: lead.notify_ref };
	// Atomic: a concurrent Investigate click can't be overwritten by a Dismiss (or vice versa).
	if (!(await dismissPendingLead(env.DB, leadId))) {
		const now = await getLead(env.DB, leadId);
		return { ok: false, summary: `Lead #${leadId} is already ${now?.status ?? "handled"}`, notifyRef: lead.notify_ref };
	}
	log("info", "lead dismissed", { leadId, actor: actor.id });
	return { ok: true, summary: `Dismissed by ${actor.label}`, notifyRef: lead.notify_ref };
}

/**
 * Deliver a human decision to a case's Workflow. The case is claimed atomically
 * (`awaiting_decision` → `applying`, with `decided_by`) BEFORE the event is sent, so
 * only one approver's decision is delivered and the Workflow's later `closed` write is
 * never overwritten. If the event can't be sent, the claim is released.
 */
export async function decideCaseAction(env: Env, caseId: string, decision: Decision, actor: Actor): Promise<ActionResult> {
	const row = await getCase(env.DB, caseId);
	if (!row) return { ok: false, summary: `Case ${caseId} not found` };
	if (row.status !== "awaiting_decision") return { ok: false, summary: alreadyDecided(row.id, row.status, row.decided_by), notifyRef: row.notify_ref };
	if (!(await claimCaseDecision(env.DB, caseId, actor.id))) {
		const now = await getCase(env.DB, caseId);
		return { ok: false, summary: alreadyDecided(caseId, now?.status ?? "unknown", now?.decided_by ?? null), notifyRef: row.notify_ref };
	}
	let status: string;
	try {
		status = await sendDecision(env, caseId, { ...decision, actor: actor.id });
	} catch (err) {
		await releaseCaseDecision(env.DB, caseId, actor.id).catch((e: unknown) =>
			log("error", "case: could not release decision claim", { caseId, error: errorMessage(e) }),
		);
		throw err;
	}
	log("info", "case decided", { caseId, action: decision.action, actor: actor.id });
	return {
		ok: true,
		summary: `Decision **${decision.action}** by ${actor.label} (Cloudflare IPs are skipped)`,
		notifyRef: row.notify_ref,
		data: { workflow: status },
	};
}

export async function approveFlagsAction(
	env: Env,
	cfg: Config,
	indicators: string[],
	opts: { ttlDays: number; action?: FlagAction },
	actor: Actor,
): Promise<ActionResult> {
	const ranges = await loadCloudflareRanges();
	const protectedOnes: string[] = [];
	const allowed: string[] = [];
	for (const i of indicators) ((await isProtectedIndicator(i, ranges)) ? protectedOnes : allowed).push(i);
	if (protectedOnes.length) await rejectFlags(env.DB, protectedOnes);
	const approved = await approveFlags(env.DB, allowed, opts);
	const waf = await syncBlocksToWaf(env, cfg, approved);
	log("info", "flags approved", { count: approved.length, protected: protectedOnes.length, waf, actor: actor.id });
	const action = opts.action ?? approved[0]?.action ?? "decoy";
	const summary =
		approved.length === 0
			? protectedOnes.length
				? `Rejected ${protectedOnes.join(", ")}: Cloudflare IP`
				: "Nothing to approve (already handled?)"
			: `**${action}** for ${approved.map((f) => f.indicator).join(", ")} by ${actor.label} (${opts.ttlDays}d, WAF: ${waf})`;
	return { ok: approved.length > 0, summary, data: { approved, protected: protectedOnes, waf } };
}

export async function rejectFlagsAction(env: Env, indicators: string[], actor: Actor): Promise<ActionResult> {
	const n = await rejectFlags(env.DB, indicators);
	log("info", "flags rejected", { count: n, actor: actor.id });
	return { ok: n > 0, summary: n > 0 ? `Rejected ${indicators.join(", ")} by ${actor.label}` : "Nothing to reject (already handled?)" };
}

/** Submit the drafted Cloudflare abuse report for a case. Explicit human action only. */
export async function submitAbuseReportAction(env: Env, cfg: Config, caseId: string, actor: Actor): Promise<ActionResult> {
	if (cfg.abuse.mode !== "submit") return { ok: false, summary: 'Abuse report submission is disabled (ABUSE_REPORTS="draft"): use the draft at abuse.cloudflare.com' };
	const row = await getCase(env.DB, caseId);
	if (!row) return { ok: false, summary: `Case ${caseId} not found` };
	if (row.hosted_on_cloudflare !== 1) return { ok: false, summary: "This copy is not on Cloudflare: report it to its host or registrar" };
	if (row.abuse_report) return { ok: false, summary: "An abuse report was already submitted or is in progress for this case", notifyRef: row.notify_ref };
	const obj = await env.EVIDENCE.get(abuseReportKey(caseId));
	if (!obj) return { ok: false, summary: "No abuse report draft found for this case" };
	const draft = (await obj.json()) as AbuseDraft;
	const reporter = parseReporter(env.ABUSE_REPORTER_JSON);
	if (!reporter) return { ok: false, summary: "ABUSE_REPORTER_JSON secret is missing or invalid (name and email required)" };
	const built = buildSubmission(draft, reporter);
	if ("missing" in built) return { ok: false, summary: `Reporter fields missing: ${built.missing.join(", ")}` };
	const api = cfApi(env);
	if (!api) return { ok: false, summary: "CF_API_TOKEN (with Trust and Safety Write) is not configured" };

	// Reserve the slot atomically: two clicks can never submit the same legal report twice.
	const marker = JSON.stringify({ status: "submitting", by: actor.id, at: new Date().toISOString() });
	if (!(await claimAbuseReport(env.DB, caseId, marker))) {
		return { ok: false, summary: "An abuse report was already submitted or is in progress for this case", notifyRef: row.notify_ref };
	}

	let result: unknown;
	try {
		result = await api.submitAbuseReport(draft.report_param, built.body);
	} catch (err) {
		log("error", "abuse report submit failed", { caseId, error: errorMessage(err) });
		await releaseAbuseReport(env.DB, caseId, marker).catch((e: unknown) =>
			log("error", "abuse report: could not release claim", { caseId, error: errorMessage(e) }),
		);
		return { ok: false, summary: `Abuse report submission failed: ${errorMessage(err).slice(0, 300)}` };
	}

	// Submitted. From here on, never release the claim: a retry would file a duplicate report.
	const record = { submittedAt: new Date().toISOString(), by: actor.id, act: draft.act, result };
	try {
		await env.EVIDENCE.put(`cases/${caseId}/abuse-report-result.json`, JSON.stringify(record, null, 2), { httpMetadata: { contentType: "application/json" } });
	} catch (err) {
		log("error", "abuse report: result not saved to R2", { caseId, error: errorMessage(err) });
	}
	await updateCase(env.DB, caseId, { abuse_report: JSON.stringify(record) });
	log("info", "abuse report submitted", { caseId, act: draft.act, actor: actor.id });
	return { ok: true, summary: `Cloudflare **${draft.act}** report submitted by ${actor.label}`, notifyRef: row.notify_ref, data: record };
}

function alreadyDecided(caseId: string, status: string, decidedBy: string | null): string {
	if (decidedBy && (status === "applying" || status === "closed")) return `Case ${caseId} was already decided by \`${decidedBy}\` (${status})`;
	return `Case ${caseId} is ${status}, not awaiting a decision`;
}
