/**
 * Collect request signals from trusted sources only:
 * - CF-Connecting-IP (set by Cloudflare, not client-spoofable when proxied)
 * - cf-ray (Cloudflare Ray ID; pivot into Security Analytics / Logpush)
 * - request.cf (ASN, geo, TLS, Bot Management fields on Enterprise zones)
 *   https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
 *   https://developers.cloudflare.com/bots/reference/bot-management-variables/#workers-variables
 */
import { nowSec, randomHex, truncate } from "../core/util";

/** Fields sealed inside the token (survive forever, no storage needed). */
export interface Fingerprint {
	issuedAt: number;
	ip: string;
	asn: number;
	country: string;
	colo: string;
	/** 1-99 when Bot Management is present, otherwise null. */
	botScore: number | null;
	/**
	 * Cloudflare verified this bot (search engine, monitoring, archiver…). Workers can't read
	 * Rulesets fields such as `cf.client.bot` / `cf.bot_management.verified_bot`; the runtime
	 * equivalents are `request.cf.botManagement.verifiedBot` and `request.cf.verifiedBotCategory`,
	 * and either one sets this bit (sealed in the token, so case decisions can skip the IP).
	 * Both come with Bot Management: without it the Worker sees neither.
	 */
	verifiedBot: boolean;
	jsDetectionPassed: boolean;
	botManagement: boolean;
	/** 16 hex characters. */
	rayId: string;
}

/** Fingerprint plus richer, non-sealed fields written to Analytics Engine. */
export interface RequestSignals extends Fingerprint {
	host: string;
	path: string;
	method: string;
	userAgent: string;
	ja4: string;
	ja3Hash: string;
	detectionIds: number[];
	verifiedBotCategory: string;
	asOrganization: string;
	city: string;
	httpProtocol: string;
	tlsVersion: string;
	clientTcpRtt: number | null;
	referer: string;
	acceptLanguage: string;
	/** `CF-Worker` header: zone of a Cloudflare Worker that made this subrequest (abuse-report evidence). */
	cfWorker: string;
	/** `Sec-Fetch-Dest` (document, script, image, empty, …); distinguishes navigations from hotlinks. */
	fetchDest: string;
}

interface CfLike {
	asn?: number;
	asOrganization?: string;
	country?: string | null;
	colo?: string;
	city?: string;
	httpProtocol?: string;
	tlsVersion?: string;
	clientTcpRtt?: number;
	verifiedBotCategory?: string;
	botManagement?: {
		score?: number;
		verifiedBot?: boolean;
		staticResource?: boolean;
		ja3Hash?: string;
		ja4?: string;
		detectionIds?: number[];
		jsDetection?: { passed?: boolean };
	} | null;
}

const RAY = /^([0-9a-f]{16})/i;

export function collectSignals(request: Request): RequestSignals {
	const url = new URL(request.url);
	const cf = (request.cf ?? {}) as CfLike;
	const bm = cf.botManagement ?? null;
	const rayMatch = RAY.exec(request.headers.get("cf-ray") ?? "");
	const score = typeof bm?.score === "number" && bm.score >= 1 && bm.score <= 99 ? bm.score : null;

	return {
		issuedAt: nowSec(),
		ip: request.headers.get("cf-connecting-ip") ?? "::",
		asn: typeof cf.asn === "number" ? cf.asn : 0,
		country: (cf.country ?? "XX").slice(0, 2).toUpperCase(),
		colo: (cf.colo ?? "---").slice(0, 3).toUpperCase(),
		botScore: score,
		verifiedBot: bm?.verifiedBot === true || (typeof cf.verifiedBotCategory === "string" && cf.verifiedBotCategory.length > 0),
		jsDetectionPassed: bm?.jsDetection?.passed === true,
		botManagement: bm !== null && score !== null,
		// Local dev has no cf-ray: fall back to a random id with the same shape.
		rayId: (rayMatch?.[1] ?? randomHex(8)).toLowerCase(),

		host: url.hostname,
		path: truncate(url.pathname + url.search, 512),
		method: request.method,
		userAgent: truncate(request.headers.get("user-agent"), 512),
		ja4: truncate(bm?.ja4, 64),
		ja3Hash: truncate(bm?.ja3Hash, 64),
		detectionIds: Array.isArray(bm?.detectionIds) ? bm.detectionIds.slice(0, 32) : [],
		verifiedBotCategory: truncate(cf.verifiedBotCategory, 64),
		asOrganization: truncate(cf.asOrganization, 128),
		city: truncate(cf.city, 64),
		httpProtocol: truncate(cf.httpProtocol, 16),
		tlsVersion: truncate(cf.tlsVersion, 16),
		clientTcpRtt: typeof cf.clientTcpRtt === "number" ? cf.clientTcpRtt : null,
		referer: truncate(request.headers.get("referer"), 512),
		acceptLanguage: truncate(request.headers.get("accept-language"), 128),
		cfWorker: truncate(request.headers.get("cf-worker"), 256),
		fetchDest: truncate(request.headers.get("sec-fetch-dest"), 32).toLowerCase(),
	};
}

/**
 * Signals of a clone's *visitor*, an innocent third party (beacon requests and hotlinked
 * assets loaded by a browser rendering a copied page). Keeps what describes the clone
 * (our host and path, coarse country/colo, the clone page as Referer) and drops everything
 * that describes or could find the person. That includes the Ray ID, which pivots into
 * Cloudflare logs that hold their IP.
 */
export function scrubVisitorSignals(s: RequestSignals): RequestSignals {
	return {
		...s,
		ip: "",
		ja4: "",
		ja3Hash: "",
		acceptLanguage: "",
		userAgent: "",
		city: "",
		asOrganization: "",
		asn: 0,
		clientTcpRtt: null,
		detectionIds: [],
		cfWorker: "",
		rayId: "",
	};
}

/** Verified bots (search engines etc.) are never flagged. */
export function isVerifiedBot(s: RequestSignals): boolean {
	return s.verifiedBot || s.verifiedBotCategory.length > 0;
}
