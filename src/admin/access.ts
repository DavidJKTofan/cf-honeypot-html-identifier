/**
 * Cloudflare Access in front of the admin API.
 *
 * Access authenticates every request to ADMIN_PREFIX at the edge (an Owner login in a
 * browser, or a service token for the CLI) and forwards a signed JWT in the
 * `Cf-Access-Jwt-Assertion` header. The Worker verifies that JWT itself (signature against
 * the team's public keys, audience, issuer, expiry), so a missing or deleted Access app
 * fails closed instead of exposing the API.
 * https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
 */
import type { AccessConfig } from "../core/config";
import { b64urlDecode, errorMessage, log } from "../core/util";

export type AccessIdentity =
	/** A person who passed an Allow policy (for example "Allow · Owner (Passkey)"). */
	| { kind: "user"; email: string }
	/** A service token that passed a Service Auth policy; `clientId` is its (non-secret) Client ID. */
	| { kind: "service"; clientId: string };

type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

interface Jwk extends JsonWebKey {
	kid?: string;
}

const SKEW_SEC = 60;
const decoder = new TextDecoder();

function decodeJson(part: string): Record<string, unknown> | null {
	const bytes = b64urlDecode(part);
	if (!bytes) return null;
	try {
		const v: unknown = JSON.parse(decoder.decode(bytes));
		return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
	} catch {
		return null;
	}
}

/**
 * Public keys of the team. Edge-cached for 5 minutes; on an unknown `kid` (key rotation)
 * the caller refetches once without the cache. No module-level state (Workers best practice).
 */
async function fetchKeys(cfg: AccessConfig, fetcher: FetchFn, fresh: boolean): Promise<Jwk[]> {
	const init: RequestInit = fresh ? { cache: "no-store" } : { cf: { cacheTtl: 300, cacheEverything: true } };
	const res = await fetcher(`${cfg.teamDomain}/cdn-cgi/access/certs`, { ...init, signal: AbortSignal.timeout(5_000) });
	if (!res.ok) throw new Error(`access certs: HTTP ${res.status}`);
	const body = (await res.json()) as { keys?: Jwk[] };
	return Array.isArray(body.keys) ? body.keys : [];
}

/**
 * Verify an Access JWT. Returns the identity, or null for anything that is not a valid,
 * current token for this application (never throws).
 */
export async function verifyAccessJwt(
	token: string,
	cfg: AccessConfig,
	opts: { fetcher?: FetchFn; nowSec?: number } = {},
): Promise<AccessIdentity | null> {
	const fetcher = opts.fetcher ?? ((input, init) => fetch(input, init));
	const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
	const deny = (reason: string) => {
		log("warn", "admin: access jwt rejected", { reason });
		return null;
	};
	try {
		const parts = token.split(".");
		if (parts.length !== 3) return deny("malformed");
		const [h = "", p = "", sig = ""] = parts;
		const header = decodeJson(h);
		const payload = decodeJson(p);
		if (!header || !payload) return deny("undecodable");
		if (header.alg !== "RS256" || typeof header.kid !== "string") return deny("unexpected alg or kid");

		const aud = payload.aud;
		if (!(aud === cfg.aud || (Array.isArray(aud) && aud.includes(cfg.aud)))) return deny("audience");
		if (payload.iss !== cfg.teamDomain) return deny("issuer");
		if (typeof payload.exp !== "number" || payload.exp + SKEW_SEC < now) return deny("expired");
		if (typeof payload.nbf === "number" && payload.nbf - SKEW_SEC > now) return deny("not yet valid");

		let jwk = (await fetchKeys(cfg, fetcher, false)).find((k) => k.kid === header.kid);
		jwk ??= (await fetchKeys(cfg, fetcher, true)).find((k) => k.kid === header.kid);
		if (!jwk) return deny("unknown kid");
		const signature = b64urlDecode(sig);
		if (!signature) return deny("signature encoding");
		const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
		const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, new TextEncoder().encode(`${h}.${p}`));
		if (!valid) return deny("signature");

		if (typeof payload.email === "string" && payload.email) return { kind: "user", email: payload.email.toLowerCase() };
		if (typeof payload.common_name === "string" && payload.common_name) return { kind: "service", clientId: payload.common_name };
		return deny("no identity claim");
	} catch (err) {
		return deny(`error: ${errorMessage(err)}`);
	}
}
