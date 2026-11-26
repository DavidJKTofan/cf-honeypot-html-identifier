/**
 * Approval actions, shared by every human entry point (admin API / CLI,
 * Discord buttons, future Slack or Telegram adapters). Each returns a short
 * human-readable summary; none throws for expected refusals.
 */
import type { Config } from "../core/config";
import { errorMessage, log, nowSec, safeUrl } from "../core/util";
import { abuseReportKey, caseKey } from "../workflows/report";
import { cfApi, type CfApi, type SubmittedAbuseReport } from "../integrations/cloudflare/api";
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
	swapAbuseReport,
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
	if (row.abuse_report) return { ok: false, summary: abuseTaken(caseId, row.abuse_report), notifyRef: row.notify_ref };
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
		return { ok: false, summary: abuseTaken(caseId, (await getCase(env.DB, caseId))?.abuse_report ?? null), notifyRef: row.notify_ref };
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
		await env.EVIDENCE.put(abuseResultKey(caseId), JSON.stringify(record, null, 2), { httpMetadata: { contentType: "application/json" } });
	} catch (err) {
		log("error", "abuse report: result not saved to R2", { caseId, error: errorMessage(err) });
	}
	await updateCase(env.DB, caseId, { abuse_report: JSON.stringify(record) });
	log("info", "abuse report submitted", { caseId, act: draft.act, actor: actor.id });
	return { ok: true, summary: `Cloudflare **${draft.act}** report submitted by ${actor.label}`, notifyRef: row.notify_ref, data: record };
}

const abuseResultKey = (caseId: string) => caseKey(caseId, "abuse-report-result.json");

function abuseTaken(caseId: string, value: string | null): string {
	const base = "An abuse report was already submitted or is in progress for this case";
	return value && parseSubmittingMarker(value)
		? `${base}. If it has been in progress for over ${ABUSE_RESET_MIN_AGE_SEC / 60} minutes, the submission died: \`npm run hp -- abuse-report-reset ${caseId}\` checks the submitted reports and clears it`
		: base;
}

/**
 * A `submitting` claim younger than this may still be running (a submission is one API call
 * of at most ~30 s), and a report filed moments ago may not be listed yet: never reset it.
 */
export const ABUSE_RESET_MIN_AGE_SEC = 600;
/** Submitted reports listed before a reset: 5 pages of 200. More means "can't be sure". */
const ABUSE_RESET_MAX_PAGES = 5;
/** Clock skew allowed between this Worker and the Abuse Reports API. */
const ABUSE_RESET_SKEW_SEC = 300;

/** The `submitting` claim written by `submitAbuseReportAction`, or null for anything else (a submitted record). */
function parseSubmittingMarker(value: string): { by: string | null; at: number } | null {
	try {
		const m = JSON.parse(value) as { status?: unknown; by?: unknown; at?: unknown };
		if (m?.status !== "submitting" || typeof m.at !== "string") return null;
		const at = Date.parse(m.at);
		return Number.isFinite(at) ? { by: typeof m.by === "string" ? m.by : null, at: Math.floor(at / 1000) } : null;
	} catch {
		return null;
	}
}

/** Same host, or one is a subdomain of the other (`www.copy.example` vs `copy.example`). */
function relatedHost(a: string, b: string): boolean {
	const x = a.toLowerCase().replace(/\.$/, "");
	const y = b.toLowerCase().replace(/\.$/, "");
	return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

/**
 * Reports this account submitted since `sinceSec` that could be this case's: on a related
 * host, or with no domain at all (counted, to be safe). Null when the listing was too long
 * to read completely.
 */
async function submittedReportsFor(api: CfApi, host: string, sinceSec: number): Promise<SubmittedAbuseReport[] | null> {
	const createdAfter = new Date((sinceSec - ABUSE_RESET_SKEW_SEC) * 1000).toISOString();
	const matches: SubmittedAbuseReport[] = [];
	for (let page = 1; ; page++) {
		const r = await api.listSubmittedAbuseReports({ createdAfter, page, perPage: 200 });
		matches.push(...r.reports.filter((rep) => !rep.domain || relatedHost(rep.domain, host)));
		const last = r.totalPages === null ? r.reports.length < 200 : page >= r.totalPages;
		if (last) return matches;
		if (page >= ABUSE_RESET_MAX_PAGES) return null;
	}
}

/**
 * Clear a stuck `submitting` abuse-report claim (the Worker died during the API call), so
 * the report can be submitted again. Explicit human action (admin API only). It never
 * clears a report that was filed:
 * 1. only a `submitting` marker older than `ABUSE_RESET_MIN_AGE_SEC` qualifies;
 * 2. a result saved to R2, or a report in the account's submitted reports for this host
 *    since the claim, means it was filed: that record replaces the marker instead;
 * 3. the marker is cleared with a conditional write (`abuse_report = <marker>`), so a
 *    concurrent change is never overwritten.
 */
export async function resetAbuseReportAction(
	env: Env,
	caseId: string,
	actor: Actor,
	opts: { api?: CfApi | null; now?: number } = {},
): Promise<ActionResult> {
	const row = await getCase(env.DB, caseId);
	if (!row) return { ok: false, summary: `Case ${caseId} not found` };
	const marker = row.abuse_report;
	if (!marker) return { ok: false, summary: "Nothing to reset: no abuse report is in progress for this case" };
	const claim = parseSubmittingMarker(marker);
	if (!claim) return { ok: false, summary: "The abuse report for this case was submitted: it is never reset (a retry would file a duplicate)" };
	const age = (opts.now ?? nowSec()) - claim.at;
	if (age < ABUSE_RESET_MIN_AGE_SEC) {
		return { ok: false, summary: `The submission started ${Math.max(0, age)}s ago and may still be running: try again in ${ABUSE_RESET_MIN_AGE_SEC - age}s` };
	}

	// The Worker may have died after the API call, between the R2 and the D1 write.
	const saved = await env.EVIDENCE.get(abuseResultKey(caseId));
	if (saved) {
		const text = (await saved.text()).slice(0, 10_000);
		const recorded = await swapAbuseReport(env.DB, caseId, marker, text);
		log("warn", "abuse report reset refused: result saved in R2", { caseId, recorded, actor: actor.id });
		return { ok: false, summary: `Not reset: the report was submitted (result saved in R2${recorded ? ", now recorded on the case" : ""})`, data: { recorded } };
	}

	const api = opts.api !== undefined ? opts.api : cfApi(env);
	if (!api) return { ok: false, summary: "Not reset: CF_API_TOKEN (Trust and Safety Read or Write) is needed to check the submitted reports first" };
	let found: SubmittedAbuseReport[] | null;
	try {
		found = await submittedReportsFor(api, row.host, claim.at);
	} catch (err) {
		log("error", "abuse report reset: listing submitted reports failed", { caseId, error: errorMessage(err) });
		return { ok: false, summary: `Not reset: could not check the submitted reports (${errorMessage(err).slice(0, 200)})` };
	}
	if (found === null) {
		return { ok: false, summary: `Not reset: more than ${ABUSE_RESET_MAX_PAGES * 200} reports were submitted since the claim, so this one can't be ruled out. Check the dashboard (Abuse reports)` };
	}
	if (found.length > 0) {
		const reports = found.slice(0, 10).map((r) => ({ id: r.id, cdate: r.cdate ?? null, domain: r.domain ?? null, status: r.status ?? null, type: r.type ?? null }));
		const record = { recoveredAt: new Date().toISOString(), recoveredBy: actor.id, claimedBy: claim.by, note: "found in the account's submitted reports after a stuck claim", reports };
		const recorded = await swapAbuseReport(env.DB, caseId, marker, JSON.stringify(record));
		log("warn", "abuse report reset refused: a submitted report was found", { caseId, reports: reports.map((r) => r.id), recorded, actor: actor.id });
		return {
			ok: false,
			summary: `Not reset: ${found.length} report(s) for ${row.host} were submitted since the claim (${reports.map((r) => r.id).join(", ")})${recorded ? "; recorded on the case" : ""}`,
			data: { reports, recorded },
		};
	}

	if (!(await releaseAbuseReport(env.DB, caseId, marker))) {
		return { ok: false, summary: "Not reset: the case's abuse report changed meanwhile. Check it again" };
	}
	log("info", "abuse report claim reset", { caseId, claimedBy: claim.by, ageSec: age, actor: actor.id });
	return { ok: true, summary: `Stuck abuse report claim cleared by ${actor.label}: no report was filed, so it can be submitted again`, data: { claimedBy: claim.by, ageSec: age } };
}

function alreadyDecided(caseId: string, status: string, decidedBy: string | null): string {
	if (decidedBy && (status === "applying" || status === "closed")) return `Case ${caseId} was already decided by \`${decidedBy}\` (${status})`;
	return `Case ${caseId} is ${status}, not awaiting a decision`;
}
