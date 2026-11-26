/**
 * Shared by the admin decode endpoint and the InvestigateWorkflow:
 * fetch a suspected copy, extract carriers, open tokens, enrich from WAE.
 */
import type { FoundToken } from "../identity/carriers";
import { lookupRay, type RayEnrichment } from "../storage/analytics";
import type { Fingerprint } from "../identity/fingerprint";
import { loadTokenKeys, logRetiredKeys, openToken, type OpenedToken, type TokenVersion } from "../identity/token";
import { errorMessage, sha256Hex } from "../core/util";
import { DEFAULT_CAPTURE_USER_AGENT } from "../core/config";

export const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;

export interface DecodedToken {
	carrier: string;
	token: string;
	valid: boolean;
	fingerprint: Fingerprint | null;
	issuedAtIso: string | null;
	/** Token format (null when invalid). */
	version: TokenVersion | null;
	/** Ring ID that opened a version 2 token (null for v1 or invalid). */
	keyId: number | null;
	/** Sealed with a key that no longer seals new tokens (see `OpenedToken.retired`). */
	retiredKey: boolean;
	enrichment?: RayEnrichment | null;
	enrichmentError?: string;
}

export async function decodeTokens(
	env: Env,
	found: FoundToken[],
	opts: { enrich: boolean; maxEnrich?: number; source?: "decode" | "workflow" },
): Promise<DecodedToken[]> {
	const ring = await loadTokenKeys(env);
	const out: DecodedToken[] = [];
	const opened: OpenedToken[] = [];
	for (const f of found) {
		const t = await openToken(f.token, ring);
		if (t) opened.push(t);
		const fp = t?.fingerprint ?? null;
		out.push({
			carrier: f.carrier,
			token: f.token,
			valid: fp !== null,
			fingerprint: fp,
			issuedAtIso: fp ? new Date(fp.issuedAt * 1000).toISOString() : null,
			version: t?.version ?? null,
			keyId: t?.keyId ?? null,
			retiredKey: t?.retired ?? false,
		});
	}
	logRetiredKeys(opts.source ?? "decode", opened, ring.currentKeyId);
	if (opts.enrich) {
		let budget = opts.maxEnrich ?? 20;
		for (const d of out) {
			if (!d.fingerprint || budget-- <= 0) continue;
			try {
				d.enrichment = await lookupRay(env, d.fingerprint.rayId, d.fingerprint.issuedAt);
			} catch (err) {
				d.enrichment = null;
				d.enrichmentError = errorMessage(err);
			}
		}
	}
	return out;
}

export interface CapturedPage {
	/** The captured body: the whole page, or its first `maxBytes` when `truncated`. */
	bytes: Uint8Array;
	status: number;
	finalUrl: string;
	contentType: string;
	/** SHA-256 of `bytes`, i.e. of exactly what was captured (a prefix when `truncated`). */
	sha256: string;
	fetchedAt: string;
	headers: Record<string, string>;
	/** True when the page was larger than the cap and only its first `maxBytes` were kept. */
	truncated: boolean;
}

const KEEP_HEADERS = [
	"content-type",
	"server",
	"cf-ray",
	"x-powered-by",
	"via",
	"last-modified",
	"date",
	"content-length",
	// Set only on error pages Cloudflare generates itself (not forwarded origin errors):
	// https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-error-headers/
	"cf-error-type",
	"cf-error-origin",
];

/** Characters of an error page that `describeErrorPage` returns: enough for `error code: 1016` or a page title. */
const ERROR_PREVIEW_CHARS = 200;

export interface ErrorPage {
	/** Cloudflare error code from the `cf-error-type` header, else from an `error code: 1xxx` body; null if neither. */
	cloudflareError: string | null;
	/** The page's `<title>`, else the start of its body, as plain text. Untrusted: show it as data. */
	preview: string;
}

/**
 * Describe a capture that isn't a 2xx page, e.g. HTTP 530 `error code: 1016` (Cloudflare
 * couldn't resolve the host's origin). No page was served, so a missing token proves nothing.
 * Returns null for a 2xx response.
 */
export function describeErrorPage(page: Pick<CapturedPage, "status" | "bytes" | "headers">): ErrorPage | null {
	if (page.status >= 200 && page.status < 300) return null;
	const raw = new TextDecoder().decode(page.bytes.subarray(0, 8192));
	const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(raw)?.[1];
	const preview = (title ?? raw)
		.replace(/<[^>]*>/g, " ")
		// Drop control characters (C0, DEL, C1): this is a third-party page printed in a terminal.
		.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, ERROR_PREVIEW_CHARS);
	const header = (page.headers["cf-error-type"] ?? "").trim();
	const cloudflareError = /^\d{3,4}$/.test(header) ? header : (/\berror(?: code:)? (1\d{3})\b/i.exec(raw)?.[1] ?? null);
	return { cloudflareError, preview };
}

type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Read at most `maxBytes` of a stream, then cancel the rest. Never throws for size:
 * a padded clone must not be able to make the evidence capture fail, and our tokens
 * sit in <head>, so the first bytes are the ones that matter.
 */
async function readPrefix(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<{ bytes: Uint8Array; truncated: boolean }> {
	if (!body) return { bytes: new Uint8Array(), truncated: false };
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	let truncated = false;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		if (total + value.byteLength > maxBytes) {
			chunks.push(value.subarray(0, maxBytes - total));
			total = maxBytes;
			truncated = true;
			await reader.cancel();
			break;
		}
		chunks.push(value);
		total += value.byteLength;
	}
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		bytes.set(c, offset);
		offset += c.byteLength;
	}
	return { bytes, truncated };
}

/**
 * Fetch a suspected clone with a size cap and timeout. Pages above `maxBytes` are
 * truncated (`truncated: true`), not rejected; the hash then covers the captured prefix.
 *
 * Sends ordinary browser headers (`userAgent` = CAPTURE_USER_AGENT): a self-identifying
 * UA lets a clone serve a token-free page to the capture only. Two tells remain that a
 * Worker can't remove: the `CF-Worker` header and Cloudflare's egress ASN. The lead's
 * beacon token covers that case (see InvestigateWorkflow), and Browser Run capture is
 * on the roadmap.
 */
export async function fetchPage(
	url: string,
	maxBytes = MAX_CAPTURE_BYTES,
	fetcher: FetchFn = (input, init) => fetch(input, init),
	userAgent: string = DEFAULT_CAPTURE_USER_AGENT,
): Promise<CapturedPage> {
	const res = await fetcher(url, {
		redirect: "follow",
		headers: {
			accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"accept-language": "en-US,en;q=0.9",
			"user-agent": userAgent,
		},
		signal: AbortSignal.timeout(15_000),
	});
	const { bytes, truncated } = await readPrefix(res.body, maxBytes);
	const headers: Record<string, string> = {};
	for (const h of KEEP_HEADERS) {
		const v = res.headers.get(h);
		if (v) headers[h] = v;
	}
	return {
		bytes,
		status: res.status,
		finalUrl: res.url || url,
		contentType: res.headers.get("content-type") ?? "",
		sha256: await sha256Hex(bytes),
		fetchedAt: new Date().toISOString(),
		headers,
		truncated,
	};
}
