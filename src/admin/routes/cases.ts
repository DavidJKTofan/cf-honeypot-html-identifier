/**
 * GET /cases · POST /cases {url} · GET /cases/:id · GET /cases/:id/report[?format=json]
 * GET /cases/:id/evidence/:file · POST /cases/:id/decision · POST /cases/:id/abuse-report
 */
import { decideCaseAction, submitAbuseReportAction } from "../../approvals/actions";
import { CaseInputError, parseDecision, startInvestigation } from "../../approvals/cases";
import { errorMessage, json, readJson } from "../../core/util";
import { resolveSafe } from "../../notify";
import { getCase, getCaseTokens, listCases } from "../../storage/d1";
import { caseKey } from "../../workflows/report";
import { badRequest, type AdminRoute } from "../context";

const EVIDENCE_TYPES: Record<string, string> = {
	"report.json": "application/json; charset=utf-8",
	"report.md": "text/markdown; charset=utf-8",
	"snapshot.html": "text/plain; charset=utf-8", // never render captured HTML
	"urlscan.json": "application/json; charset=utf-8",
	"intel.json": "application/json; charset=utf-8",
	"screenshot.png": "image/png",
	"decision.json": "application/json; charset=utf-8",
	"abuse-report-draft.json": "application/json; charset=utf-8",
	"abuse-report-result.json": "application/json; charset=utf-8",
};

export const caseRoutes: AdminRoute = async ({ request, env, cfg, method, path, seg, url, actor }) => {
	if (method === "GET" && path === "/cases") return json({ cases: await listCases(env.DB) });
	if (method === "POST" && path === "/cases") {
		const body = await readJson<{ url?: string }>(request);
		if (!body?.url) return badRequest('expected {"url": "https://suspected-clone.example/page"}');
		try {
			return json({ ok: true, ...(await startInvestigation(env, cfg, { url: body.url, leadId: null })) }, { status: 202 });
		} catch (err) {
			if (err instanceof CaseInputError) return badRequest(err.message);
			throw err;
		}
	}
	if (seg[0] !== "cases" || !seg[1]) return null;

	const caseId = seg[1];
	const row = await getCase(env.DB, caseId);
	if (!row) return json({ error: "case not found" }, { status: 404 });

	if (method === "GET" && seg.length === 2) {
		let workflow: unknown;
		try {
			workflow = await (await env.INVESTIGATE.get(caseId)).status();
		} catch (err) {
			workflow = { error: errorMessage(err) };
		}
		return json({ case: row, tokens: await getCaseTokens(env.DB, caseId), workflow });
	}

	if (method === "GET" && (seg[2] === "report" || seg[2] === "evidence")) {
		const name = seg[2] === "report" ? (url.searchParams.get("format") === "json" ? "report.json" : "report.md") : (seg[3] ?? "");
		const type = EVIDENCE_TYPES[name];
		if (!type) return json({ error: `unknown evidence file; one of ${Object.keys(EVIDENCE_TYPES).join(", ")}` }, { status: 404 });
		const obj = await env.EVIDENCE.get(caseKey(caseId, name));
		if (!obj) return json({ error: "not available (yet)" }, { status: 404 });
		return new Response(obj.body, {
			headers: { "content-type": type, "cache-control": "no-store", "content-security-policy": "sandbox; default-src 'none'", "x-content-type-options": "nosniff" },
		});
	}

	if (method === "POST" && seg[2] === "decision") {
		const decision = parseDecision(await readJson(request));
		if (!decision) return badRequest('expected {"action": "decoy" | "block" | "none", "ttlDays"?, "ips"?, "note"?}');
		const result = await decideCaseAction(env, caseId, decision, actor);
		if (result.ok) await resolveSafe(env, cfg, result.notifyRef ?? null, result.summary);
		return json(result, { status: result.ok ? 202 : 409 });
	}

	if (method === "POST" && seg[2] === "abuse-report") {
		const result = await submitAbuseReportAction(env, cfg, caseId, actor);
		return json(result, { status: result.ok ? 201 : 409 });
	}
	return null;
};
