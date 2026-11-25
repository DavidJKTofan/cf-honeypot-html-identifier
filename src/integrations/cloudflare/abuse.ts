/**
 * Cloudflare abuse report drafts for copies proxied by / hosted on Cloudflare.
 * https://developers.cloudflare.com/fundamentals/reference/report-abuse/submit-report/
 * API: POST /accounts/{account_id}/abuse-reports/{report_param} (Trust and Safety Write).
 *
 * The Workflow only DRAFTS a report (no personal data stored in the draft).
 * Submitting is a separate, explicit human action, and DMCA reports are legal
 * statements made under penalty of perjury: review every field first.
 * If the copy is not on Cloudflare, report it to its host / registrar instead.
 */
import type { AbuseAct } from "../../core/config";

export interface ReporterContact {
	name: string;
	email: string;
	company?: string;
	tele?: string;
	address1?: string;
	city?: string;
	state?: string;
	country?: string;
	/** Copyright holder (DMCA). Defaults to company or name. */
	agent_name?: string;
}

export interface DraftInput {
	act: AbuseAct;
	caseId: string;
	cloneUrls: string[];
	originalUrl: string;
	sha256: string;
	capturedAt: string;
	rayIds: string[];
	/** CF-Worker zones of scrapers that fetched our page from a Cloudflare Worker (lets Cloudflare find the Worker). */
	workerZones?: string[];
	/** The copy is a live reverse proxy (token minted during the capture). */
	liveMirror?: boolean;
}

export interface AbuseDraft {
	act: AbuseAct;
	/** Path segment for the API (`{report_param}`): the report type, the same value as `act`. */
	report_param: AbuseAct;
	/** Fields without reporter identity; merged with ABUSE_REPORTER_JSON at submit time. */
	fields: Record<string, string | number>;
	required_reporter_fields: string[];
	notes: string[];
}

const REPORTER_FIELDS: Record<AbuseAct, string[]> = {
	abuse_dmca: ["name", "email", "address1", "city", "state", "country", "agent_name"],
	abuse_phishing: ["name", "email"],
	abuse_general: ["name", "email"],
};

export function draftAbuseReport(d: DraftInput): AbuseDraft {
	const urls = [...new Set(d.cloneUrls)].slice(0, 250).join("\n");
	const zones = [...new Set(d.workerZones ?? [])].slice(0, 5);
	const evidence =
		`Case ${d.caseId}. Captured ${d.capturedAt}, SHA-256 ${d.sha256}. The page contains our AES-GCM sealed ` +
		`identifier(s) issued for request(s) ${d.rayIds.slice(0, 10).join(", ")}, proving it is a copy of ${d.originalUrl}.` +
		(d.liveMirror ? " The copy is a live reverse proxy: it fetches our page for every visitor." : "") +
		(zones.length ? ` Our page was fetched by a Cloudflare Worker (CF-Worker: ${zones.join(", ")}).` : "");
	const fields: Record<string, string | number> = { act: d.act, urls, comments: evidence.slice(0, 2000) };
	if (d.act === "abuse_dmca") {
		// No `agree` here: it is a statement under penalty of perjury, added by buildSubmission
		// only when a human explicitly submits (it is never pre-filled in a draft).
		Object.assign(fields, { original_work: d.originalUrl.slice(0, 255), host_notification: "send", owner_notification: "send" });
	} else {
		Object.assign(fields, {
			original_work: d.originalUrl.slice(0, 255),
			host_notification: "send",
			owner_notification: "send",
			justification:
				`This site serves an unauthorized copy of ${d.originalUrl} (verbatim HTML including our hidden identifiers), ` +
				"impersonating our site to its visitors.",
		});
	}
	return {
		act: d.act,
		report_param: d.act,
		fields,
		required_reporter_fields: REPORTER_FIELDS[d.act],
		notes: [
			"Draft only: review every field before submitting. Nothing has been sent.",
			"Cloudflare notifies the hosting provider and site owner (host_notification / owner_notification = send).",
			d.act === "abuse_dmca"
				? "DMCA reports cannot be anonymous; `signature` (your full name) and `agree: 1` are statements under penalty of perjury. Neither is in this draft: they are added only when a human submits."
				: "Phishing/general reports may use send-anon notifications if you prefer.",
			"Submit via https://abuse.cloudflare.com/ or the admin API (ABUSE_REPORTS=submit + ABUSE_REPORTER_JSON).",
		],
	};
}

export function parseReporter(json: string | undefined): ReporterContact | null {
	if (!json) return null;
	try {
		const r = JSON.parse(json) as Partial<ReporterContact>;
		return r.name && r.email ? (r as ReporterContact) : null;
	} catch {
		return null;
	}
}

/** Merge the draft with the reporter identity; returns the API body or the list of missing fields. */
export function buildSubmission(draft: AbuseDraft, reporter: ReporterContact): { body: Record<string, unknown> } | { missing: string[] } {
	const identity: Record<string, string | undefined> = {
		...reporter,
		agent_name: reporter.agent_name ?? reporter.company ?? reporter.name,
	};
	const missing = draft.required_reporter_fields.filter((f) => !identity[f]);
	if (missing.length > 0) return { missing };
	const body: Record<string, unknown> = { ...draft.fields, name: reporter.name, email: reporter.email, email2: reporter.email };
	for (const k of ["company", "tele"] as const) if (reporter[k]) body[k] = reporter[k];
	if (draft.act === "abuse_dmca") {
		Object.assign(body, {
			address1: identity.address1,
			city: identity.city,
			state: identity.state,
			country: identity.country,
			agent_name: identity.agent_name,
			signature: reporter.name,
			// The human's explicit submit action is the agreement; drafts never carry it.
			agree: 1,
		});
	}
	return { body };
}
