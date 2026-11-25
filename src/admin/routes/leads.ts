/** GET /leads?status= · POST /leads/:id/approve {url?} · POST /leads/:id/dismiss */
import { approveLeadAction, dismissLeadAction } from "../../approvals/actions";
import { json, readJson } from "../../core/util";
import { resolveSafe } from "../../notify";
import { listLeads, type LeadStatus } from "../../storage/d1";
import type { AdminRoute } from "../context";

export const leadRoutes: AdminRoute = async ({ request, env, cfg, method, path, seg, url, actor }) => {
	if (method === "GET" && path === "/leads") {
		const s = url.searchParams.get("status") ?? "pending";
		const status: LeadStatus | null = s === "pending" || s === "approved" || s === "dismissed" ? s : null;
		return json({ leads: await listLeads(env.DB, status) });
	}
	if (method !== "POST" || seg[0] !== "leads" || seg.length !== 3) return null;

	const id = Number(seg[1]);
	if (!Number.isInteger(id)) return json({ error: "lead id must be a number" }, { status: 400 });
	const result =
		seg[2] === "approve"
			? await approveLeadAction(env, cfg, id, actor, ((await readJson<{ url?: string }>(request)) ?? {}).url)
			: seg[2] === "dismiss"
				? await dismissLeadAction(env, id, actor)
				: null;
	if (!result) return null;
	if (result.ok) await resolveSafe(env, cfg, result.notifyRef ?? null, result.summary);
	return json(result, { status: result.ok ? (seg[2] === "approve" ? 202 : 200) : 409 });
};
