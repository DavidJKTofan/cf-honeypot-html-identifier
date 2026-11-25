/**
 * Pure evidence helpers for the InvestigateWorkflow (no I/O, unit-tested).
 */
import { isCloudflareIp, type CloudflareRanges } from "../integrations/cloudflare/ip-ranges";
import type { TokenEvidence } from "./types";

/**
 * A token issued at most this many seconds before the capture was minted BY the capture:
 * the copy is a live reverse proxy that fetched our page when the investigator fetched it.
 */
export const LIVE_MIRROR_MAX_SEC = 30;

/** Analytics Engine ingestion lags up to about a minute; Ray lookups for fresher tokens wait first. */
export const INGESTION_WAIT_WINDOW_SEC = 120;

export function secondsBeforeCapture(issuedAt: number, capturedAtIso: string): number {
	const captured = Date.parse(capturedAtIso);
	return Number.isFinite(captured) ? Math.round(captured / 1000 - issuedAt) : Number.POSITIVE_INFINITY;
}

export function isLiveMirror(t: Pick<TokenEvidence, "secondsBeforeCapture" | "source">): boolean {
	return t.source === "capture" && t.secondsBeforeCapture >= -5 && t.secondsBeforeCapture <= LIVE_MIRROR_MAX_SEC;
}

/** True when at least one token is so fresh that its Analytics Engine row may not be queryable yet. */
export function needsIngestionWait(tokens: Pick<TokenEvidence, "secondsBeforeCapture">[]): boolean {
	return tokens.some((t) => t.secondsBeforeCapture <= INGESTION_WAIT_WINDOW_SEC);
}

export interface DecisionTargets {
	/** IPs the decision may flag. */
	act: string[];
	/** Cloudflare IPs: never flagged (abuse report instead). */
	skippedCloudflareIps: string[];
	/** IPs whose token says the fetch was a verified bot: never flagged. */
	skippedVerifiedBotIps: string[];
}

/**
 * Which of the case's scraper IPs a decision may act on. `wanted` limits it to a subset
 * (decision.ips); IPs that are not in the case are ignored. Cloudflare IPs and verified
 * bots (a clone made from a crawler's or archiver's fetch would otherwise frame Googlebot)
 * are skipped and reported.
 */
export function decisionTargets(tokens: Pick<TokenEvidence, "fingerprint">[], wanted: string[] | undefined, ranges: CloudflareRanges): DecisionTargets {
	const caseIps = [...new Set(tokens.map((t) => t.fingerprint.ip))];
	const chosen = wanted?.length ? caseIps.filter((ip) => wanted.includes(ip)) : caseIps;
	const verified = new Set(tokens.filter((t) => t.fingerprint.verifiedBot).map((t) => t.fingerprint.ip));
	const out: DecisionTargets = { act: [], skippedCloudflareIps: [], skippedVerifiedBotIps: [] };
	for (const ip of chosen) {
		if (isCloudflareIp(ip, ranges)) out.skippedCloudflareIps.push(ip);
		else if (verified.has(ip)) out.skippedVerifiedBotIps.push(ip);
		else out.act.push(ip);
	}
	return out;
}
