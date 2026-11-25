/**
 * Typed view over the Worker's `vars` (wrangler.jsonc). Parsed per request:
 * cheap, and avoids module-level mutable state.
 */

export type Carrier = "meta" | "trap" | "beacon" | "zw" | "form";
export type NotifyChannel = "discord" | "discord-webhook" | "none";
export type AbuseAct = "abuse_dmca" | "abuse_phishing" | "abuse_general";

const ALL_CARRIERS: readonly Carrier[] = ["meta", "trap", "beacon", "zw", "form"];

/** Benign "foreign hosts" that legitimately render or reference your pages. */
const BUILTIN_IGNORE = ["translate.goog", "archive.org", "archive.ph", "webcache.googleusercontent.com"];

/**
 * Default evidence-capture User-Agent: an ordinary desktop browser. A self-identifying UA
 * ("…-investigator") lets a clone serve a token-free page to the capture only (cloaking).
 * Override with CAPTURE_USER_AGENT; keep it current-ish.
 */
export const DEFAULT_CAPTURE_USER_AGENT =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

export interface Config {
	canonicalHosts: Set<string>;
	adminPrefix: string;
	trapPath: string;
	beaconPath: string;
	beaconScriptPath: string;
	carriers: Set<Carrier>;
	metaName: string;
	formField: string;
	tarpitMs: number;
	flagTtlDays: number;
	pendingTtlDays: number;
	refererIgnore: string[];
	accountId: string;
	wafListId: string;
	urlscanVisibility: "Unlisted" | "Public";
	intelMaxIpsPerCase: number;
	/** User-Agent of the evidence capture (and admin decode by URL). Browser-like so clones can't cloak by UA. */
	captureUserAgent: string;
	/** https://<first canonical host>, used for "original work" links in reports. */
	siteOrigin: string;
	notify: {
		channel: NotifyChannel;
		discord: {
			applicationId: string;
			publicKey: string;
			channelId: string;
			approverIds: Set<string>;
			approverRoleIds: Set<string>;
			interactionsPath: string;
			apiBase: string;
		};
	};
	abuse: { mode: "draft" | "submit"; act: AbuseAct };
	/** Cloudflare Access in front of ADMIN_PREFIX (ACCESS_TEAM_DOMAIN + ACCESS_AUD secrets), or null = bearer token. */
	access: AccessConfig | null;
}

function list(value: string | undefined): string[] {
	return (value ?? "")
		.split(",")
		.map((v) => v.trim().toLowerCase())
		.filter(Boolean);
}

function int(value: string | undefined, fallback: number, min = 0): number {
	const n = Number.parseInt(value ?? "", 10);
	return Number.isFinite(n) && n >= min ? n : fallback;
}

function path(value: string | undefined, fallback: string): string {
	const v = (value ?? "").trim();
	return v.startsWith("/") ? v.replace(/\/+$/, "") || "/" : fallback;
}

function ids(value: string | undefined): Set<string> {
	return new Set(list(value).filter((v) => /^\d{5,25}$/.test(v)));
}

export function loadConfig(env: Env): Config {
	const canonical = list(env.CANONICAL_HOSTS);
	const channel = env.NOTIFY_CHANNEL === "discord" || env.NOTIFY_CHANNEL === "discord-webhook" ? env.NOTIFY_CHANNEL : "none";
	const act = env.ABUSE_REPORT_TYPE === "abuse_phishing" || env.ABUSE_REPORT_TYPE === "abuse_general" ? env.ABUSE_REPORT_TYPE : "abuse_dmca";
	const carriers = new Set(list(env.CARRIERS).filter((c): c is Carrier => (ALL_CARRIERS as string[]).includes(c)));
	return {
		canonicalHosts: new Set(canonical),
		adminPrefix: path(env.ADMIN_PREFIX, "/__hp"),
		trapPath: path(env.TRAP_PATH, "/catalog/full-export"),
		beaconPath: path(env.BEACON_PATH, "/api/rum"),
		beaconScriptPath: path(env.BEACON_SCRIPT_PATH, "/assets/js/rum.js"),
		carriers,
		metaName: (env.META_NAME || "csrf-token").trim(),
		formField: (env.FORM_FIELD || "_csrf").trim(),
		tarpitMs: int(env.TARPIT_MS, 5000),
		flagTtlDays: int(env.FLAG_TTL_DAYS, 7, 1),
		pendingTtlDays: int(env.PENDING_TTL_DAYS, 14, 1),
		refererIgnore: [...BUILTIN_IGNORE, ...list(env.REFERER_IGNORE)],
		accountId: (env.ACCOUNT_ID ?? "").trim(),
		wafListId: (env.WAF_LIST_ID ?? "").trim(),
		urlscanVisibility: env.URLSCAN_VISIBILITY === "Public" ? "Public" : "Unlisted",
		intelMaxIpsPerCase: int(env.INTEL_MAX_IPS_PER_CASE, 3),
		captureUserAgent: (env.CAPTURE_USER_AGENT ?? "").trim().slice(0, 512) || DEFAULT_CAPTURE_USER_AGENT,
		siteOrigin: `https://${canonical[0] ?? "localhost"}`,
		notify: {
			channel,
			discord: {
				applicationId: (env.DISCORD_APPLICATION_ID ?? "").trim(),
				publicKey: (env.DISCORD_PUBLIC_KEY ?? "").trim().toLowerCase(),
				channelId: (env.DISCORD_CHANNEL_ID ?? "").trim(),
				approverIds: ids(env.DISCORD_APPROVER_IDS),
				approverRoleIds: ids(env.DISCORD_APPROVER_ROLE_IDS),
				interactionsPath: path(env.DISCORD_INTERACTIONS_PATH, "/integrations/discord/interactions"),
				apiBase: (env.DISCORD_API_BASE || "https://discord.com/api/v10").replace(/\/+$/, ""),
			},
		},
		abuse: { mode: env.ABUSE_REPORTS === "submit" ? "submit" : "draft", act },
		access: accessConfig(env.ACCESS_TEAM_DOMAIN, env.ACCESS_AUD),
	};
}

export interface AccessConfig {
	/** https://<team>.cloudflareaccess.com (the JWT issuer). */
	teamDomain: string;
	/** Application Audience (AUD) tag of the Access app that protects ADMIN_PREFIX. */
	aud: string;
}

/** Both secrets set → Access is required for the admin API. Otherwise the bearer token is used. */
export function accessConfig(teamDomain: string | undefined, aud: string | undefined): AccessConfig | null {
	const team = (teamDomain ?? "").trim().replace(/\/+$/, "").replace(/^https?:\/\//, "");
	const audience = (aud ?? "").trim();
	return team && audience ? { teamDomain: `https://${team}`, aud: audience } : null;
}

export function isCanonicalHost(cfg: Config, host: string): boolean {
	return cfg.canonicalHosts.has(host.toLowerCase());
}
