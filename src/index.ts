/**
 * cf-honeypot-html-identifier
 *
 * Educational, defensive MVP: every HTML page carries a sealed, hidden
 * identifier so a scraped copy can be traced back to the request that fetched
 * it; a beacon, foreign-Referer monitoring and Brand Protection surface clones;
 * a Workflow builds an evidence bundle; enforcement needs human approval.
 */
import { handleAdmin } from "./admin/router";
import { handleDiscordInteraction } from "./notify/discord/interactions";
import { beaconScriptResponse, handleBeacon } from "./honeypot/beacon";
import { injectCarriers } from "./identity/carriers";
import { loadConfig } from "./core/config";
import { writeEvent } from "./storage/analytics";
import { collectSignals, isVerifiedBot } from "./identity/fingerprint";
import { decoyResponse, flagIndicators, handleTrap, noteForeignReferer, robotsResponse, tarpit } from "./honeypot/trap";
import { activeFlagAction } from "./storage/d1";
import { importTokenKey, sealToken } from "./identity/token";
import { errorMessage, isHtmlResponse, isStaticAsset, log } from "./core/util";

export { InvestigateWorkflow } from "./workflows/investigate";
export { MaintenanceWorkflow } from "./workflows/maintenance";

/** Demo: serve the bundled static site. Production: forward to your origin. */
function upstream(request: Request, env: Env): Promise<Response> {
	return env.ASSETS ? env.ASSETS.fetch(request) : fetch(request);
}

async function handle(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	const cfg = loadConfig(env);
	const url = new URL(request.url);
	const path = url.pathname;

	if (path === cfg.adminPrefix || path.startsWith(`${cfg.adminPrefix}/`)) return handleAdmin(request, env, ctx, cfg);
	// Signed button clicks from Discord approval messages (src/notify/discord/README.md).
	if (path === cfg.notify.discord.interactionsPath && request.method === "POST") return handleDiscordInteraction(request, env, ctx, cfg);
	// The beacon records its own (privacy-scrubbed) event; never count it as a hotlink.
	if (path === cfg.beaconPath && request.method === "POST") return handleBeacon(request, env, ctx, cfg);

	const s = collectSignals(request);
	// Before any other route: a clone hotlinking the beacon script or assets is itself a signal.
	noteForeignReferer(env, cfg, s, path === cfg.beaconScriptPath || isStaticAsset(request, url));

	if (path === cfg.beaconScriptPath) return beaconScriptResponse(url.origin, cfg);
	if (path === cfg.trapPath) return handleTrap(env, ctx, cfg, s, url.origin);
	if (path === "/robots.txt") return robotsResponse(await upstream(request, env), cfg);
	if (isStaticAsset(request, url)) return upstream(request, env);

	// Flag lookup runs in parallel with the upstream fetch for reads (hides D1 latency);
	// for writes it runs first, so an approved-flagged actor never reaches the origin.
	const isRead = request.method === "GET" || request.method === "HEAD";
	const indicators = flagIndicators(s);
	let action: Awaited<ReturnType<typeof activeFlagAction>>;
	let response: Response | null = null;
	if (isRead) [action, response] = await Promise.all([activeFlagAction(env.DB, indicators), upstream(request, env)]);
	else action = await activeFlagAction(env.DB, indicators);
	// Never enforce on a verified bot, even if its IP was flagged (manually, or shared with a scraper).
	if (action && isVerifiedBot(s)) {
		log("warn", "flag matched a verified bot: not enforced", { action, ip: s.ip, category: s.verifiedBotCategory || null });
		action = null;
	}

	if (action === "block") {
		await response?.body?.cancel();
		return new Response("Forbidden", { status: 403 }); // fallback if the WAF list rule is absent
	}
	if (action === "decoy") {
		await response?.body?.cancel();
		writeEvent(env, "decoy", s);
		await tarpit(cfg.tarpitMs);
		return decoyResponse(env, cfg, s, url.origin);
	}

	response ??= await upstream(request, env);
	// 206: a byte range of the page. Rewriting it would corrupt the range (and mint a token nobody sees).
	if (!isHtmlResponse(response) || response.status === 206) return response;

	const token = await sealToken(s, await importTokenKey(env.TOKEN_KEY));
	writeEvent(env, "page", s);
	return injectCarriers(response, { token, cfg, origin: url.origin });
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		try {
			return await handle(request, env, ctx);
		} catch (err) {
			log("error", "request failed", { path: new URL(request.url).pathname, error: errorMessage(err) });
			// Explicit, logged fail-open for idempotent reads keeps the site up without a token.
			if (request.method === "GET" || request.method === "HEAD") {
				try {
					return await upstream(request, env);
				} catch {
					// fall through
				}
			}
			return new Response("Internal Server Error", { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;
