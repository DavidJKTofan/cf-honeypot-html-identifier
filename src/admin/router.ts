/**
 * Admin API under ADMIN_PREFIX (default /__hp). Endpoints: src/admin/openapi.yaml.
 *
 * Authentication, one of:
 * - Cloudflare Access (production): ACCESS_TEAM_DOMAIN + ACCESS_AUD set. Access authenticates
 *   at the edge (Owner login or service token) and the Worker verifies the forwarded JWT.
 *   The bearer token is then ignored, and actions are attributed to the JWT identity.
 * - Bearer ADMIN_TOKEN (local dev, or no Access app): compared in constant time.
 * Anything unauthenticated gets a plain 404 so the surface is not advertised.
 *
 * Every enforcement path is an explicit human action (see src/approvals/).
 */
import type { Config } from "../core/config";
import { BodyTooLargeError, errorMessage, json, log, notFound, timingSafeEqualStr } from "../core/util";
import type { Actor } from "../approvals/actions";
import { verifyAccessJwt } from "./access";
import { ADMIN_ACTOR, type AdminContext, type AdminRoute } from "./context";
import { caseRoutes } from "./routes/cases";
import { decodeRoutes } from "./routes/decode";
import { flagRoutes } from "./routes/flags";
import { leadRoutes } from "./routes/leads";
import { opsRoutes } from "./routes/ops";

const ROUTES: AdminRoute[] = [decodeRoutes, leadRoutes, caseRoutes, flagRoutes, opsRoutes];

/** Who is calling, or null (→ 404). With Access configured, only a valid Access JWT counts. */
export async function authenticate(request: Request, env: Env, cfg: Config): Promise<Actor | null> {
	if (cfg.access) {
		const jwt = request.headers.get("cf-access-jwt-assertion");
		if (!jwt) return null;
		const id = await verifyAccessJwt(jwt, cfg.access);
		if (!id) return null;
		return id.kind === "user"
			? { id: `access:${id.email}`, label: id.email }
			: { id: `access-service:${id.clientId}`, label: `Access service token ${id.clientId.slice(0, 8)}…` };
	}
	const expected = env.ADMIN_TOKEN;
	if (!expected) return null;
	const header = request.headers.get("authorization") ?? "";
	return (await timingSafeEqualStr(header.startsWith("Bearer ") ? header.slice(7) : "", expected)) ? ADMIN_ACTOR : null;
}

export async function handleAdmin(request: Request, env: Env, ctx: ExecutionContext, cfg: Config): Promise<Response> {
	const actor = await authenticate(request, env, cfg);
	if (!actor) return notFound();

	const url = new URL(request.url);
	const path = url.pathname.slice(cfg.adminPrefix.length).replace(/\/+$/, "") || "/";
	const c: AdminContext = { request, env, ctx, cfg, url, method: request.method, path, seg: path.split("/").filter(Boolean), actor };

	try {
		for (const route of ROUTES) {
			const res = await route(c);
			if (res) return res;
		}
		return json({ error: "unknown admin route" }, { status: 404 });
	} catch (err) {
		if (err instanceof BodyTooLargeError) return json({ error: "body too large" }, { status: 413 });
		log("error", "admin request failed", { path, method: c.method, error: errorMessage(err) });
		return json({ error: "internal error", detail: errorMessage(err) }, { status: 500 });
	}
}
