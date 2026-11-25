/**
 * Honeypot behaviour: hidden trap link, decoy content and tarpit.
 *
 * Nothing here enforces anything on its own: a trap hit only records a PENDING
 * flag. Decoys are served to an IP only after a human approves its flag.
 */
import { injectCarriers } from "../identity/carriers";
import { isCanonicalHost, type Config } from "../core/config";
import { writeEvent } from "../storage/analytics";
import { isVerifiedBot, scrubVisitorSignals, type RequestSignals } from "../identity/fingerprint";
import { isCloudflareIp, loadCloudflareRanges } from "../integrations/cloudflare/ip-ranges";
import { indicatorFor, recordPendingFlag } from "../storage/d1";
import { importTokenKey, sealToken } from "../identity/token";
import { BodyTooLargeError, errorMessage, hostMatchesSuffix, log, randomInt, readStreamLimited } from "../core/util";

/** Indicators checked on every non-static request. */
export function flagIndicators(s: RequestSignals): string[] {
	const out = [indicatorFor("ip", s.ip)];
	if (s.ja4) out.push(indicatorFor("ja4", s.ja4));
	return out;
}

/** Wall-clock delay: costs the scraper time, costs us no billed CPU time. */
export async function tarpit(ms: number): Promise<void> {
	if (ms <= 0) return;
	await scheduler.wait(ms + randomInt(1000));
}

const DECOY_ROWS = [
	["CAT-1042", "Trail Compass Pro", "49.90"],
	["CAT-2210", "Ridge Shell Jacket", "189.00"],
	["CAT-3377", "Summit Pack 28L", "129.50"],
	["CAT-4108", "Valley Water Filter", "39.00"],
	["CAT-5521", "Canyon Trekking Poles", "74.00"],
];

function decoyHtml(): string {
	const rows = DECOY_ROWS.map(
		([sku, name, price]) => `<tr><td>${sku}</td><td>${name}</td><td>${(Number(price) * (0.9 + randomInt(20) / 100)).toFixed(2)}</td></tr>`,
	).join("");
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">
<title>Catalog export</title><link rel="icon" href="/favicon.ico" sizes="any"><link rel="icon" type="image/png" href="/favicon.png">
<link rel="stylesheet" href="/styles.css"></head><body><main class="container">
<h1>Catalog export</h1><p>Export generated for your session. Showing the first ${DECOY_ROWS.length} items.</p>
<table><thead><tr><th>SKU</th><th>Item</th><th>Price (EUR)</th></tr></thead><tbody>${rows}</tbody></table>
<p>Need the full dataset? Use the paginated export endpoint.</p></main></body></html>`;
}

/** Decoy response. Still carries a fresh token, so a republished decoy is attributable too. */
export async function decoyResponse(env: Env, cfg: Config, s: RequestSignals, origin: string): Promise<Response> {
	const token = await sealToken(s, await importTokenKey(env.TOKEN_KEY));
	if (s.path.startsWith("/api/")) {
		return Response.json(
			{
				data: DECOY_ROWS.map(([sku, name, price]) => ({ sku, name, price: Number(price) })),
				meta: { page: 1, total: DECOY_ROWS.length, request_id: token },
			},
			{ headers: { "cache-control": "private, no-store" } },
		);
	}
	const page = new Response(decoyHtml(), { headers: { "content-type": "text/html; charset=utf-8" } });
	return injectCarriers(page, { token, cfg, origin });
}

export async function handleTrap(
	env: Env,
	ctx: ExecutionContext,
	cfg: Config,
	s: RequestSignals,
	origin: string,
): Promise<Response> {
	writeEvent(env, "trap", s);

	const likelyHuman = s.botManagement && (s.botScore ?? 0) >= 30;
	if (isVerifiedBot(s)) {
		log("info", "trap: verified bot ignored", { ip: s.ip, category: s.verifiedBotCategory });
	} else if (isCloudflareIp(s.ip, await loadCloudflareRanges())) {
		// Cloudflare itself or a customer's Worker (see CF-Worker): report abuse, never flag.
		log("info", "trap: cloudflare ip ignored", { ip: s.ip, cfWorker: s.cfWorker || null });
	} else if (likelyHuman) {
		log("info", "trap: likely human (bot score >= 30), not flagged", { ip: s.ip, score: s.botScore });
	} else if ((await env.TRAP_LIMITER.limit({ key: `trap:${s.ip}` })).success) {
		// Per IP first (so repeat hits from one IP don't use up the global budget), then a
		// global bound: a crawl spread over many proxy IPs still costs few D1 writes.
		if (!(await env.TRAP_GLOBAL_LIMITER.limit({ key: "trap" })).success) {
			log("warn", "trap: global pending-flag budget exhausted, not recorded", { ip: s.ip, rayId: s.rayId });
		} else {
			const reason = `trap hit${s.botScore !== null ? ` (bot score ${s.botScore})` : ""}${s.ja4 ? ` ja4=${s.ja4}` : ""}`;
			ctx.waitUntil(
				recordPendingFlag(env.DB, {
					kind: "ip",
					value: s.ip,
					reason,
					sourceRef: s.rayId,
					pendingTtlDays: cfg.pendingTtlDays,
				}).catch((err: unknown) => log("error", "trap: pending flag write failed", { error: errorMessage(err) })),
			);
			log("info", "trap: pending flag recorded", { ip: s.ip, rayId: s.rayId });
		}
	}

	await tarpit(cfg.tarpitMs);
	return decoyResponse(env, cfg, s, origin);
}

/** Google and RFC 9309 parsers only need the first 500 KiB of a robots.txt. */
const MAX_ROBOTS_BYTES = 512 * 1024;
const USER_AGENT_LINE = /^\s*user-agent\s*:/i;

/**
 * Add `Disallow: <trapPath>` to EVERY user-agent group, and add a `User-agent: *`
 * group if there is none. RFC 9309 §2.2.1: a crawler that has its own group obeys
 * only that group and ignores `*`, so a trap disallowed only under `*` would still
 * be "allowed" for, say, a `User-agent: Googlebot` + `Allow: /` group.
 * https://www.rfc-editor.org/rfc/rfc9309.html#section-2.2.1
 *
 * The line goes right after each group's user-agent lines; rule order doesn't
 * matter (the longest matching path wins, so it also beats `Allow: /`). Comments
 * and blank lines don't end a user-agent run.
 */
export function addTrapDisallow(robots: string, trapPath: string): string {
	const disallow = `Disallow: ${trapPath}`;
	const out: string[] = [];
	let inUserAgents = false;
	let hasWildcard = false;
	for (const line of robots.replace(/\r\n?/g, "\n").trimEnd().split("\n")) {
		const content = line.replace(/#.*$/, "").trim();
		if (USER_AGENT_LINE.test(content)) {
			inUserAgents = true;
			if (content.slice(content.indexOf(":") + 1).trim() === "*") hasWildcard = true;
		} else if (inUserAgents && content !== "") {
			out.push(disallow);
			inUserAgents = false;
		}
		out.push(line);
	}
	if (inUserAgents) out.push(disallow);
	if (!hasWildcard) out.push("", "# Not for crawlers", "User-agent: *", disallow);
	return `${out.join("\n")}\n`;
}

/** robots.txt with the trap path disallowed for every crawler group: polite crawlers skip it, rude ones fall in. */
export async function robotsResponse(upstream: Response, cfg: Config): Promise<Response> {
	let base = "User-agent: *\nAllow: /\n";
	if (upstream.ok) {
		try {
			base = new TextDecoder().decode(await readStreamLimited(upstream.body, MAX_ROBOTS_BYTES));
		} catch (err) {
			// Oversized origin robots.txt: still serve the trap rule rather than fail.
			if (!(err instanceof BodyTooLargeError)) throw err;
			log("warn", "robots.txt: origin file too large, serving the default", { maxBytes: MAX_ROBOTS_BYTES });
		}
	} else {
		await upstream.body?.cancel();
	}
	const body = addTrapDisallow(base, cfg.trapPath);
	return new Response(body, {
		status: 200,
		headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=3600" },
	});
}

/** Subresource loads only: a link *click* from another site (a navigation) is normal traffic, not a clone. */
const SUBRESOURCE_DESTS = new Set(["script", "style", "image", "font", "audio", "video", "track", "object", "embed", "empty", "manifest", "worker"]);

/**
 * Foreign Referer on a subresource → "hotlink" analytics event (aggregated daily
 * into leads; no D1 write here). `Sec-Fetch-Dest` tells navigations apart; without
 * it (older clients, bots), only requests for static assets or the beacon count.
 *
 * A hotlink is loaded by a browser rendering the copied page, so the requester is the
 * clone's *visitor*, an innocent third party: the event is scrubbed exactly like a
 * beacon event (no IP, User-Agent, JA4, city, ASN or Ray ID). Only the clone host,
 * our path, coarse country/colo and the Referer (the clone page) are kept.
 */
export function noteForeignReferer(env: Env, cfg: Config, s: RequestSignals, looksLikeSubresource: boolean): void {
	if (!s.referer) return;
	if (s.fetchDest ? !SUBRESOURCE_DESTS.has(s.fetchDest) : !looksLikeSubresource) return;
	let host: string;
	try {
		host = new URL(s.referer).hostname.toLowerCase();
	} catch {
		return;
	}
	if (!host || isCanonicalHost(cfg, host) || hostMatchesSuffix(host, cfg.refererIgnore)) return;
	writeEvent(env, "hotlink", scrubVisitorSignals(s), { index: host, foreignHost: host });
}
