/**
 * Resetting a stuck abuse-report claim (H2 part b). A submission claims `cases.abuse_report`
 * with a `submitting` marker before the API call; if the Worker dies mid-call, only this
 * admin action can clear it, and never for a report that was actually filed.
 */
import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ABUSE_RESET_MIN_AGE_SEC, resetAbuseReportAction, submitAbuseReportAction, type Actor } from "../src/approvals/actions";
import { handleAdmin } from "../src/admin/router";
import { loadConfig } from "../src/core/config";
import { nowSec } from "../src/core/util";
import { draftAbuseReport } from "../src/integrations/cloudflare/abuse";
import { CfApi } from "../src/integrations/cloudflare/api";
import { createCase, getCase, updateCase } from "../src/storage/d1";
import { abuseReportKey, caseKey } from "../src/workflows/report";

const ADMIN: Actor = { id: "admin", label: "admin API" };
const OLD = nowSec() - ABUSE_RESET_MIN_AGE_SEC - 60;

const marker = (atSec: number, by = "discord:111111111111111111") => JSON.stringify({ status: "submitting", by, at: new Date(atSec * 1000).toISOString() });

async function stuckCase(id: string, host: string, atSec = OLD): Promise<string> {
	await createCase(env.DB, { id, leadId: null, url: `https://${host}/`, host });
	const m = marker(atSec);
	await updateCase(env.DB, id, { status: "closed", hosted_on_cloudflare: 1, abuse_report: m });
	return m;
}

interface Listed {
	query: URLSearchParams;
}

/** A CfApi answering `GET /abuse-reports/submitted` from `pages` (one array per page). */
function submittedApi(pages: Record<string, unknown>[][], opts: { status?: number; onList?: () => Promise<void> } = {}) {
	const listed: Listed[] = [];
	const fetcher = (async (input: RequestInfo | URL) => {
		const url = new URL(input instanceof Request ? input.url : String(input));
		expect(url.pathname).toBe("/client/v4/accounts/acct/abuse-reports/submitted");
		listed.push({ query: url.searchParams });
		await opts.onList?.();
		if (opts.status) return Response.json({ success: false, errors: [{ code: 10000, message: "denied" }], result: null }, { status: opts.status });
		const page = Number(url.searchParams.get("page") ?? "1");
		return Response.json({
			success: true,
			errors: [],
			messages: [],
			result: { reports: pages[page - 1] ?? [] },
			result_info: { page, per_page: 200, count: (pages[page - 1] ?? []).length, total_pages: pages.length, total_count: 0 },
		});
	}) as typeof fetch;
	return { api: new CfApi("token", "acct", { fetcher, sleep: async () => {} }), listed };
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("resetAbuseReportAction: refusals", () => {
	it("refuses when nothing is in progress, or the report was submitted", async () => {
		await createCase(env.DB, { id: "case-reset-none", leadId: null, url: "https://reset-none.example/", host: "reset-none.example" });
		const { api, listed } = submittedApi([[]]);
		expect(await resetAbuseReportAction(env, "case-reset-none", ADMIN, { api })).toMatchObject({ ok: false, summary: expect.stringContaining("Nothing to reset") });

		const record = JSON.stringify({ submittedAt: new Date().toISOString(), by: "admin", act: "abuse_dmca", result: "success" });
		await updateCase(env.DB, "case-reset-none", { abuse_report: record });
		expect(await resetAbuseReportAction(env, "case-reset-none", ADMIN, { api })).toMatchObject({ ok: false, summary: expect.stringContaining("never reset") });
		expect((await getCase(env.DB, "case-reset-none"))?.abuse_report).toBe(record);
		expect(listed).toHaveLength(0);
		expect(await resetAbuseReportAction(env, "case-reset-missing", ADMIN, { api })).toMatchObject({ ok: false, summary: expect.stringContaining("not found") });
	});

	it("refuses a claim younger than the minimum age (the submission may still be running)", async () => {
		const m = await stuckCase("case-reset-young", "reset-young.example", nowSec() - 30);
		const { api, listed } = submittedApi([[]]);
		const r = await resetAbuseReportAction(env, "case-reset-young", ADMIN, { api });
		expect(r).toMatchObject({ ok: false, summary: expect.stringContaining("may still be running") });
		expect(listed).toHaveLength(0);
		expect((await getCase(env.DB, "case-reset-young"))?.abuse_report).toBe(m);
	});

	it("refuses without an API client, or when the listing fails: the marker stays", async () => {
		const m = await stuckCase("case-reset-noapi", "reset-noapi.example");
		expect(await resetAbuseReportAction(env, "case-reset-noapi", ADMIN, { api: null })).toMatchObject({ ok: false, summary: expect.stringContaining("CF_API_TOKEN") });
		const { api } = submittedApi([], { status: 403 });
		expect(await resetAbuseReportAction(env, "case-reset-noapi", ADMIN, { api })).toMatchObject({ ok: false, summary: expect.stringContaining("could not check") });
		expect((await getCase(env.DB, "case-reset-noapi"))?.abuse_report).toBe(m);
	});

	it("refuses when more reports were submitted since the claim than it can read", async () => {
		const m = await stuckCase("case-reset-many", "reset-many.example");
		const other = (i: number) => ({ id: `r${i}`, cdate: new Date().toISOString(), domain: `other${i}.example`, status: "submitted", type: "DMCA" });
		const page = Array.from({ length: 200 }, (_, i) => other(i));
		const { api, listed } = submittedApi([page, page, page, page, page, page]);
		const r = await resetAbuseReportAction(env, "case-reset-many", ADMIN, { api });
		expect(r).toMatchObject({ ok: false, summary: expect.stringContaining("can't be ruled out") });
		expect(listed).toHaveLength(5);
		expect((await getCase(env.DB, "case-reset-many"))?.abuse_report).toBe(m);
	});
});

describe("resetAbuseReportAction: a report that was filed is never reset", () => {
	it("a submitted report for the host replaces the marker with its record", async () => {
		const m = await stuckCase("case-reset-found", "www.reset-found.example");
		const { api, listed } = submittedApi([
			[
				{ id: "abc123", cdate: new Date().toISOString(), domain: "unrelated.example", status: "submitted", type: "DMCA" },
				{ id: "def456", cdate: new Date().toISOString(), domain: "reset-found.example", status: "submitted", type: "DMCA" },
			],
		]);
		const r = await resetAbuseReportAction(env, "case-reset-found", ADMIN, { api });
		expect(r.ok).toBe(false);
		expect(r.summary).toContain("def456");
		expect(r.summary).not.toContain("abc123");
		// The listing starts before the claim (clock skew), so a report filed right at the claim counts.
		const after = Date.parse(listed[0]?.query.get("created_after") ?? "");
		expect(after).toBeLessThan(OLD * 1000);
		const stored = (await getCase(env.DB, "case-reset-found"))?.abuse_report ?? "";
		expect(stored).not.toBe(m);
		expect(JSON.parse(stored)).toMatchObject({ recoveredBy: "admin", reports: [{ id: "def456" }] });
	});

	it("a result already saved in R2 is recorded instead of reset", async () => {
		await stuckCase("case-reset-r2", "reset-r2.example");
		const saved = JSON.stringify({ submittedAt: new Date().toISOString(), by: "admin", act: "abuse_dmca", result: "success" });
		await env.EVIDENCE.put(caseKey("case-reset-r2", "abuse-report-result.json"), saved);
		const { api, listed } = submittedApi([[]]);
		const r = await resetAbuseReportAction(env, "case-reset-r2", ADMIN, { api });
		expect(r).toMatchObject({ ok: false, summary: expect.stringContaining("R2") });
		expect(listed).toHaveLength(0);
		expect((await getCase(env.DB, "case-reset-r2"))?.abuse_report).toBe(saved);
	});
});

describe("resetAbuseReportAction: clearing", () => {
	it("clears a stuck claim with no matching report, so the report can be submitted again", async () => {
		await stuckCase("case-reset-ok", "reset-ok.example");
		const { api, listed } = submittedApi([[{ id: "zzz", cdate: new Date().toISOString(), domain: "someone-else.example", status: "accepted", type: "PHISH" }]]);
		const r = await resetAbuseReportAction(env, "case-reset-ok", ADMIN, { api });
		expect(r).toMatchObject({ ok: true, summary: expect.stringContaining("cleared") });
		expect(listed).toHaveLength(1);
		expect(listed[0]?.query.get("per_page")).toBe("200");
		expect((await getCase(env.DB, "case-reset-ok"))?.abuse_report).toBeNull();
	});

	it("never overwrites a marker that changed during the check (conditional write)", async () => {
		await stuckCase("case-reset-race", "reset-race.example");
		const newer = marker(nowSec(), "discord:222222222222222222");
		const { api } = submittedApi([[]], {
			// Another approver's submission claims the case while the listing runs.
			onList: async () => {
				await env.DB.prepare("UPDATE cases SET abuse_report = ? WHERE id = ?").bind(newer, "case-reset-race").run();
			},
		});
		const r = await resetAbuseReportAction(env, "case-reset-race", ADMIN, { api });
		expect(r).toMatchObject({ ok: false, summary: expect.stringContaining("changed meanwhile") });
		expect((await getCase(env.DB, "case-reset-race"))?.abuse_report).toBe(newer);
	});

	it("is routed: POST /cases/{id}/abuse-report/reset (and the submit route still answers alone)", async () => {
		await stuckCase("case-reset-route", "reset-route.example");
		const routeEnv = { ...env, CF_API_TOKEN: "test-token", ACCOUNT_ID: "acct" } as Env;
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
			Response.json({ success: true, errors: [], messages: [], result: { reports: [] }, result_info: { page: 1, per_page: 200, count: 0, total_pages: 1, total_count: 0 } }),
		);
		const post = (path: string) =>
			handleAdmin(
				new Request(`https://honeypot.automatic-demo.com/__hp${path}`, { method: "POST", headers: { authorization: "Bearer test-admin-token" } }),
				routeEnv,
				createExecutionContext(),
				loadConfig(routeEnv),
			);
		const res = await post("/cases/case-reset-route/abuse-report/reset");
		expect(res.status).toBe(200);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect((await getCase(env.DB, "case-reset-route"))?.abuse_report).toBeNull();
		// Nothing left to reset now.
		expect((await post("/cases/case-reset-route/abuse-report/reset")).status).toBe(409);
		expect((await post("/cases/case-reset-route/abuse-report/reset/extra")).status).toBe(404);
	});

	it("the submit refusal for a stuck claim points to the reset command", async () => {
		const caseId = "case-reset-hint";
		await stuckCase(caseId, "reset-hint.example");
		const draft = draftAbuseReport({
			act: "abuse_general",
			caseId,
			cloneUrls: ["https://reset-hint.example/"],
			originalUrl: "https://honeypot.automatic-demo.com/",
			sha256: "0".repeat(64),
			capturedAt: new Date().toISOString(),
			rayIds: ["0123456789abcdef"],
		});
		await env.EVIDENCE.put(abuseReportKey(caseId), JSON.stringify(draft));
		const submitEnv = { ...env, ABUSE_REPORTS: "submit", CF_API_TOKEN: "t", ACCOUNT_ID: "acct", ABUSE_REPORTER_JSON: JSON.stringify({ name: "R", email: "r@example.com" }) } as Env;
		const r = await submitAbuseReportAction(submitEnv, loadConfig(submitEnv), caseId, ADMIN);
		expect(r.ok).toBe(false);
		expect(r.summary).toContain(`abuse-report-reset ${caseId}`);
	});
});

describe("CfApi.listSubmittedAbuseReports", () => {
	it("calls the submitted-reports endpoint and repeats array filters", async () => {
		let seen: URL | null = null;
		const api = new CfApi("token", "acct", {
			fetcher: (async (input: RequestInfo | URL) => {
				seen = new URL(input instanceof Request ? input.url : String(input));
				return Response.json({ success: true, result: { reports: [{ id: "a1", domain: "x.example" }] }, result_info: { page: 2, total_pages: 3 } });
			}) as typeof fetch,
		});
		const r = await api.listSubmittedAbuseReports({ domains: ["x.example", "www.x.example"], createdAfter: "2026-11-01T00:00:00.000Z", page: 2, perPage: 500 });
		expect(r).toEqual({ reports: [{ id: "a1", domain: "x.example" }], page: 2, totalPages: 3 });
		const url = seen as URL | null;
		expect(url?.pathname).toBe("/client/v4/accounts/acct/abuse-reports/submitted");
		expect(url?.searchParams.getAll("domain")).toEqual(["x.example", "www.x.example"]);
		expect(url?.searchParams.get("per_page")).toBe("200");
		expect(url?.searchParams.get("created_after")).toBe("2026-11-01T00:00:00.000Z");
	});
});
