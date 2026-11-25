/**
 * Clone discovery beacon.
 *
 * A tiny script (served by this Worker) runs in every page. On our canonical
 * hosts it does nothing. On any other host it sends the page's token and URL
 * back to us. The request comes from an innocent visitor of the clone, so nothing
 * that identifies the visitor is stored; only the token (who scraped the copy) and
 * the clone's host matter. A beacon only creates a PENDING lead, bounded per host,
 * per token and globally (BEACON_LIMITER, LEAD_LIMITER).
 */
import { isCanonicalHost, type Config } from "../core/config";
import { writeEvent } from "../storage/analytics";
import { collectSignals, scrubVisitorSignals, type RequestSignals } from "../identity/fingerprint";
import { recordLead } from "../approvals/leads";
import { loadTokenKeys, openToken } from "../identity/token";
import { BodyTooLargeError, errorMessage, hostMatchesSuffix, log, readStreamLimited, safeUrl, truncate } from "../core/util";

const codes = (s: string) => `[${Array.from(s, (c) => c.charCodeAt(0)).join(",")}]`;

/** Hosts and endpoint are char-code encoded so naive cloners don't rewrite them. */
export function beaconScript(origin: string, cfg: Config): string {
	const hosts = [...cfg.canonicalHosts].map(codes).join(",");
	const endpoint = codes(origin + cfg.beaconPath);
	return (
		`(function(){try{var d=document,l=location,f=function(a){return String.fromCharCode.apply(null,a)},` +
		`h=[${hosts}].map(f);if(h.indexOf(l.hostname)>-1)return;var t="",m=d.getElementsByTagName("meta");` +
		`for(var i=0;i<m.length;i++){var c=(m[i].getAttribute("content")||"").trim();if(/^[A-Za-z0-9_-]{91}$/.test(c)){t=c;break}}` +
		`var e=f(${endpoint}),p=JSON.stringify({t:t,u:l.href.slice(0,2048),r:(d.referrer||"").slice(0,512)});` +
		`if(navigator.sendBeacon&&navigator.sendBeacon(e,p))return;fetch(e,{method:"POST",body:p,keepalive:!0,mode:"no-cors"})` +
		`}catch(_){}})();\n`
	);
}

export function beaconScriptResponse(origin: string, cfg: Config): Response {
	return new Response(beaconScript(origin, cfg), {
		headers: {
			"content-type": "application/javascript; charset=utf-8",
			"cache-control": "public, max-age=3600",
			"x-content-type-options": "nosniff",
		},
	});
}

interface BeaconBody {
	t?: unknown;
	u?: unknown;
}

const NO_CONTENT = () => new Response(null, { status: 204, headers: { "access-control-allow-origin": "*" } });

/** Signals of the clone's visitor with everything personal removed (see `scrubVisitorSignals`). */
export function visitorSafeSignals(request: Request): RequestSignals {
	return scrubVisitorSignals(collectSignals(request));
}

/**
 * A browser running a copied page sends the beacon from that page, so a real `Origin`
 * header must name the same host as the reported page URL. A mismatch means someone is
 * posting forged reports from elsewhere. A missing Origin, or the literal "null" (strict
 * Referrer-Policy, sandboxed frames), is accepted: non-browser clients can omit the
 * header anyway, so this only raises the bar; the rate limits below are the real bound.
 */
function originMatches(request: Request, pageHost: string): boolean {
	const origin = request.headers.get("origin");
	if (!origin || origin === "null") return true;
	const u = safeUrl(origin);
	return u !== null && u.hostname.toLowerCase() === pageHost;
}

export async function handleBeacon(request: Request, env: Env, ctx: ExecutionContext, cfg: Config): Promise<Response> {
	let body: BeaconBody;
	try {
		const bytes = await readStreamLimited(request.body, 4096);
		body = JSON.parse(new TextDecoder().decode(bytes)) as BeaconBody;
	} catch (err) {
		if (!(err instanceof BodyTooLargeError)) log("info", "beacon: unparseable body");
		return NO_CONTENT();
	}

	const pageUrl = safeUrl(typeof body.u === "string" ? body.u : null);
	if (!pageUrl) return NO_CONTENT();
	const host = pageUrl.hostname.toLowerCase();
	if (isCanonicalHost(cfg, host) || hostMatchesSuffix(host, cfg.refererIgnore)) return NO_CONTENT();

	const s = visitorSafeSignals(request);
	if (!originMatches(request, host)) {
		writeEvent(env, "beacon_invalid", s, { index: host, foreignHost: host, note: "origin mismatch" });
		return NO_CONTENT();
	}

	// Per clone host: one popular clone can't turn every visitor into a D1 write.
	if (!(await env.BEACON_LIMITER.limit({ key: `beacon:${host}` })).success) return NO_CONTENT();

	const token = typeof body.t === "string" ? body.t.trim() : "";
	let rayId: string | null = null;
	let tokenIp: string | null = null;
	try {
		const fp = token ? await openToken(token, await loadTokenKeys(env)) : null;
		rayId = fp?.rayId ?? null;
		tokenIp = fp?.ip ?? null;
	} catch (err) {
		log("error", "beacon: token open failed", { error: errorMessage(err) });
	}

	if (!rayId) {
		// No valid token: never a lead (prevents trivial lead spam), only an analytics event.
		writeEvent(env, "beacon_invalid", s, { index: host, foreignHost: host });
		return NO_CONTENT();
	}

	// Per token: anyone can get a valid token by loading a page, so one token must not
	// fan out to many invented hosts. A real clone reuses its token per host, and the
	// per-host bound above already covers that, so dropping extra beacons only loses hit counts.
	if (!(await env.BEACON_LIMITER.limit({ key: `beacon-token:${rayId}` })).success) return NO_CONTENT();

	writeEvent(env, "beacon", s, { index: host, foreignHost: host, note: rayId });

	// Global: whatever the host or token, at most LEAD_LIMITER lead upserts per minute per location.
	if (!(await env.LEAD_LIMITER.limit({ key: "lead" })).success) {
		log("warn", "beacon: global lead budget exhausted, lead not recorded", { host });
		return NO_CONTENT();
	}

	// The token (and the scraper IP inside it) describes who fetched our page, never the
	// visitor who sent this beacon. It is evidence for a cloaked copy and detects re-scrapes.
	ctx.waitUntil(
		recordLead(env, cfg, {
			host,
			sampleUrl: truncate(pageUrl.origin + pageUrl.pathname, 512),
			source: "beacon",
			tokenRay: rayId,
			token,
			tokenIp,
		}).catch((err: unknown) => log("error", "beacon: lead upsert failed", { host, error: errorMessage(err) })),
	);
	log("info", "beacon: clone lead recorded (pending)", { host, rayId });
	return NO_CONTENT();
}
