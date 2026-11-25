/** Serializable step results shared by the investigation Workflow and its report. */
import type { Decision } from "../approvals/cases";
import type { Fingerprint } from "../identity/fingerprint";

export interface CaptureResult {
	key: string;
	sha256: string;
	status: number;
	finalUrl: string;
	bytes: number;
	/** True when the page was bigger than the 2 MiB cap and only its first bytes were captured (and hashed). */
	truncated: boolean;
	fetchedAt: string;
	headers: Record<string, string>;
}

export interface TokenEvidence {
	carrier: string;
	issuedAtIso: string;
	fingerprint: Fingerprint;
	/** The fetching IP is a Cloudflare IP (e.g. a Worker or Cloudflare service): report, never block. */
	viaCloudflare: boolean;
	/**
	 * Where the token came from: "capture" = found in the page the Workflow fetched (proof the
	 * page contains it); "beacon" = reported by a visitor's browser running the copy, while the
	 * capture found none (cloaking or an encoded token, or a forged beacon report: unconfirmed).
	 */
	source: "capture" | "beacon";
	/** Seconds between the token's issuedAt and the capture. A few seconds = a live reverse proxy. */
	secondsBeforeCapture: number;
}

export interface DecodeResult {
	beaconScript: boolean;
	trapLink: boolean;
	candidates: number;
	tokens: TokenEvidence[];
	/** True when the capture had no valid token and the evidence is the lead's beacon token only. */
	beaconOnly?: boolean;
}

export type Skipped = { skipped: string };

export type ScanSummary =
	| Skipped
	| {
			uuid: string;
			reportUrl: string | null;
			verdictMalicious: boolean | null;
			pageUrl: string | null;
			pageIp: string | null;
			pageAsn: string | null;
			pageCountry: string | null;
			screenshotKey: string | null;
	  };

export interface IpIntel {
	ip: string;
	asn: number | null;
	org: string | null;
	type: string | null;
	ptr: string | null;
}

export type IntelSummary =
	| Skipped
	| {
			key: string;
			whoisDomain: string | null;
			registrar: string | null;
			registrarAbuseEmail: string | null;
			domainCreated: string | null;
			nameservers: string[];
			ips: IpIntel[];
			errors: string[];
	  };

export interface HostingSummary {
	ips: string[];
	onCloudflare: boolean;
	error: string | null;
	/** R2 key of the Cloudflare abuse report draft (only when on Cloudflare and the capture holds a token). */
	abuseDraftKey: string | null;
	/** Why no draft was written although the copy is on Cloudflare (e.g. beacon-only evidence). */
	abuseDraftSkipped?: string | null;
}

export interface AppliedDecision {
	action: Decision["action"];
	indicators: string[];
	skippedCloudflareIps: string[];
	/** IPs whose token says the fetch was a verified bot (search engine, archiver…): never flagged. */
	skippedVerifiedBotIps?: string[];
	/** Outcome of the decision's single WAF list write (`WafSync`, or "error" after the step's retries). */
	waf: string[];
	ttlDays: number;
	note: string | null;
	actor: string | null;
}

export const isSkipped = (x: object): x is Skipped => "skipped" in x;

export function str(v: unknown): string | null {
	return typeof v === "string" && v ? v : null;
}

export function get(obj: unknown, ...path: string[]): unknown {
	let cur = obj;
	for (const p of path) {
		if (!cur || typeof cur !== "object") return undefined;
		cur = (cur as Record<string, unknown>)[p];
	}
	return cur;
}
