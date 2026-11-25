/**
 * Case lifecycle: an approved lead (or a manual URL) starts one
 * InvestigateWorkflow instance; a human decision is delivered as an event.
 */
import { isCanonicalHost, type Config } from "../core/config";
import { claimLead, createCase, isUniqueViolation, openCaseForHost, releaseLead, setLeadStatus, updateCase } from "../storage/d1";
import { errorMessage, log, randomHex, safeUrl } from "../core/util";

export interface InvestigateParams {
	caseId: string;
	url: string;
	host: string;
	leadId: number | null;
}

export type DecisionAction = "decoy" | "block" | "none";

export interface Decision {
	action: DecisionAction;
	/** Defaults to FLAG_TTL_DAYS. */
	ttlDays?: number;
	/** Subset of the case's scraper IPs; defaults to all of them. */
	ips?: string[];
	note?: string;
	/** Who decided, e.g. "discord:123456789012345678" or "admin". */
	actor?: string;
}

export const DECISION_EVENT = "decision";

export class CaseInputError extends Error {}

/**
 * Start one InvestigateWorkflow for an approved lead (or a manual URL).
 *
 * Safe under concurrent approvals:
 * 1. the lead is claimed atomically (`pending` → `approved`), so only one caller proceeds;
 * 2. a partial UNIQUE index (migration 0003) lets the database refuse a second open
 *    case for the same host, even for manual cases;
 * 3. if the Workflow can't be created, the case is marked `errored` and the lead goes
 *    back to `pending`, so nothing is left blocking the host.
 */
export async function startInvestigation(
	env: Env,
	cfg: Config,
	input: { url: string; leadId: number | null },
): Promise<{ caseId: string; url: string; host: string }> {
	const u = safeUrl(input.url);
	if (!u) throw new CaseInputError("url must be an absolute http(s) URL");
	if (isCanonicalHost(cfg, u.hostname)) throw new CaseInputError("refusing to investigate our own canonical host");
	const host = u.hostname.toLowerCase();
	const leadId = input.leadId;

	if (leadId !== null && !(await claimLead(env.DB, leadId))) {
		throw new CaseInputError(`lead #${leadId} is no longer pending (already approved or dismissed)`);
	}

	const caseId = `case-${Date.now().toString(36)}-${randomHex(4)}`;
	let created = false;
	try {
		// Friendly early refusal; the UNIQUE index below is the real guarantee.
		const open = await openCaseForHost(env.DB, host);
		if (open) throw new CaseInputError(`case ${open.id} is already ${open.status} for ${open.host}`);

		const params: InvestigateParams = { caseId, url: u.href, host, leadId };
		try {
			await createCase(env.DB, { id: caseId, leadId, url: params.url, host });
		} catch (err) {
			if (isUniqueViolation(err)) throw new CaseInputError(`another investigation is already open for ${host}`);
			throw err;
		}
		created = true;
		await env.INVESTIGATE.create({ id: caseId, params });
	} catch (err) {
		if (created) {
			// The row exists but no Workflow will ever move it: close it so the host isn't blocked.
			await updateCase(env.DB, caseId, { status: "errored" }).catch((e: unknown) =>
				log("error", "case: could not mark failed start as errored", { caseId, error: errorMessage(e) }),
			);
		}
		if (leadId !== null) {
			await releaseLead(env.DB, leadId).catch((e: unknown) =>
				log("error", "case: could not release lead after failed start", { leadId, error: errorMessage(e) }),
			);
		}
		throw err;
	}

	if (leadId !== null) {
		// The lead is already `approved` (claimed above); this only links the case.
		await setLeadStatus(env.DB, leadId, "approved", caseId).catch((e: unknown) =>
			log("warn", "case: could not link lead to case", { leadId, caseId, error: errorMessage(e) }),
		);
	}
	return { caseId, url: u.href, host };
}

export function parseDecision(body: unknown): Decision | null {
	if (!body || typeof body !== "object") return null;
	const b = body as Record<string, unknown>;
	if (b.action !== "decoy" && b.action !== "block" && b.action !== "none") return null;
	const decision: Decision = { action: b.action };
	// Whole days, at least 1: Math.floor(0.5) would be an instantly expired flag.
	if (typeof b.ttlDays === "number" && b.ttlDays > 0 && b.ttlDays <= 365) decision.ttlDays = Math.max(1, Math.floor(b.ttlDays));
	if (Array.isArray(b.ips)) decision.ips = b.ips.filter((x): x is string => typeof x === "string").slice(0, 100);
	if (typeof b.note === "string") decision.note = b.note.slice(0, 500);
	return decision;
}

/**
 * Deliver a decision to the case's Workflow. Throws only if the event was not sent;
 * a failing status lookup afterwards returns "unknown" (the event is already delivered).
 */
export async function sendDecision(env: Env, caseId: string, decision: Decision): Promise<string> {
	const instance = await env.INVESTIGATE.get(caseId);
	await instance.sendEvent({ type: DECISION_EVENT, payload: decision });
	try {
		return (await instance.status()).status;
	} catch {
		return "unknown";
	}
}
