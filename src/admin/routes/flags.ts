/**
 * GET /flags?status= · POST /flags {ip|ja4, action?, reason?, ttlDays?}
 * POST /flags/approve {indicators | all, action?, ttlDays?} · POST /flags/reject {indicators}
 * DELETE /flags/:indicator
 */
import { approveFlagsAction, rejectFlagsAction } from "../../approvals/actions";
import { applyFlag, InvalidIndicatorError, normalizeIndicatorValue, ProtectedIpError, removeFlag } from "../../approvals/enforce";
import { json, readJson } from "../../core/util";
import { indicatorFor, listFlags, parseIndicator, type FlagAction, type FlagStatus } from "../../storage/d1";
import { badRequest, ttlFrom, type AdminRoute } from "../context";

interface FlagBody {
	ip?: string;
	ja4?: string;
	action?: FlagAction;
	reason?: string;
	ttlDays?: number;
}

interface ApproveBody {
	indicators?: string[];
	all?: boolean;
	action?: FlagAction;
	ttlDays?: number;
}

export const flagRoutes: AdminRoute = async ({ request, env, cfg, method, path, seg, url, actor }) => {
	if (method === "GET" && path === "/flags") {
		const s = url.searchParams.get("status");
		const status: FlagStatus | null = s === "pending" || s === "active" || s === "rejected" ? s : null;
		return json({ flags: await listFlags(env.DB, status) });
	}

	if (method === "POST" && path === "/flags") {
		const body = await readJson<FlagBody>(request);
		const kind = typeof body?.ip === "string" && body.ip ? "ip" : typeof body?.ja4 === "string" && body.ja4 ? "ja4" : null;
		if (!kind) return badRequest('expected {"ip" | "ja4", "action"?: "decoy" | "block", "reason"?, "ttlDays"?}');
		try {
			const result = await applyFlag(env, cfg, {
				kind,
				value: (kind === "ip" ? body?.ip : body?.ja4) ?? "",
				action: body?.action === "block" ? "block" : "decoy",
				reason: typeof body?.reason === "string" ? body.reason.slice(0, 200) : "manual",
				source: "manual",
				sourceRef: null,
				ttlDays: ttlFrom(body?.ttlDays, cfg.flagTtlDays),
			});
			const warning = kind === "ja4" ? "JA4 identifies a TLS client stack shared by many real users; prefer IP flags." : undefined;
			return json({ ok: true, ...result, warning }, { status: 201 });
		} catch (err) {
			if (err instanceof ProtectedIpError || err instanceof InvalidIndicatorError) return badRequest(err.message);
			throw err;
		}
	}

	if (method === "POST" && (path === "/flags/approve" || path === "/flags/reject")) {
		const body = (await readJson<ApproveBody>(request)) ?? {};
		const indicators = body.all
			? (await listFlags(env.DB, "pending", 500)).map((f) => f.indicator)
			: (body.indicators ?? []).filter((i) => typeof i === "string" && parseIndicator(i));
		if (indicators.length === 0) return badRequest('expected {"indicators": ["ip:203.0.113.7"]} or {"all": true}');
		const result =
			path === "/flags/reject"
				? await rejectFlagsAction(env, indicators, actor)
				: await approveFlagsAction(
						env,
						cfg,
						indicators,
						{ ttlDays: ttlFrom(body.ttlDays, cfg.flagTtlDays), action: body.action === "block" || body.action === "decoy" ? body.action : undefined },
						actor,
					);
		return json(result);
	}

	if (method === "DELETE" && seg[0] === "flags" && seg[1]) {
		let raw: string;
		try {
			raw = decodeURIComponent(seg.slice(1).join("/"));
		} catch {
			return badRequest("indicator is not valid URL encoding");
		}
		const parsed = parseIndicator(raw);
		if (!parsed) return badRequest("indicator must look like ip:203.0.113.7 or ja4:...");
		let value: string;
		try {
			value = normalizeIndicatorValue(parsed.kind, parsed.value);
		} catch (err) {
			if (err instanceof InvalidIndicatorError) return badRequest(err.message);
			throw err;
		}
		let result = await removeFlag(env, cfg, indicatorFor(parsed.kind, value));
		// Rows written before IPs were canonicalised may use another spelling of the same address.
		if (!result.flag && value !== parsed.value.trim().toLowerCase()) result = await removeFlag(env, cfg, indicatorFor(parsed.kind, parsed.value));
		const note = result.waf === "error" ? "The WAF list item could not be removed now; daily maintenance removes it." : undefined;
		return json({ ok: result.flag !== null, ...result, note }, { status: result.flag ? 200 : 404 });
	}
	return null;
};
