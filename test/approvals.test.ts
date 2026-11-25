import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { approveLeadAction, decideCaseAction, submitAbuseReportAction, type Actor } from "../src/approvals/actions";
import { CaseInputError, startInvestigation } from "../src/approvals/cases";
import { loadConfig } from "../src/core/config";
import { draftAbuseReport } from "../src/integrations/cloudflare/abuse";
import {
	approveFlags,
	createCase,
	getCase,
	getLead,
	recordPendingFlag,
	rejectFlags,
	updateCase,
	upsertActiveFlag,
	upsertLead,
	type CaseRow,
} from "../src/storage/d1";
import { abuseReportKey } from "../src/workflows/report";

const ALICE: Actor = { id: "discord:111111111111111111", label: "Alice" };
const BOB: Actor = { id: "discord:222222222222222222", label: "Bob" };

/** A stand-in for the InvestigateWorkflow binding: records calls, never runs a real Workflow. */
function fakeWorkflow(opts: { createFails?: boolean; sendFails?: boolean } = {}) {
	const calls = { create: 0, sendEvent: 0 };
	const binding = {
		async create({ id }: { id: string }) {
			calls.create++;
			await scheduler.wait(5);
			if (opts.createFails) throw new Error("workflow create failed (test)");
			return { id };
		},
		async get(id: string) {
			return {
				id,
				async sendEvent() {
					calls.sendEvent++;
					await scheduler.wait(5);
					if (opts.sendFails) throw new Error("sendEvent failed (test)");
				},
				async status() {
					return { status: "running" };
				},
			};
		},
	};
	return { calls, env: { ...env, INVESTIGATE: binding as unknown as Workflow } as Env };
}

async function casesFor(host: string): Promise<CaseRow[]> {
	return (await env.DB.prepare(`SELECT * FROM cases WHERE host = ? ORDER BY created_at`).bind(host).all<CaseRow>()).results;
}

async function newLead(host: string): Promise<number> {
	const r = await upsertLead(env.DB, { host, sampleUrl: `https://${host}/page`, source: "beacon", tokenRay: "0123456789abcdef" });
	if (!r) throw new Error("lead not created");
	return r.lead.id;
}

async function caseAwaitingDecision(id: string, host: string): Promise<void> {
	await createCase(env.DB, { id, leadId: null, url: `https://${host}/`, host });
	await updateCase(env.DB, id, { status: "awaiting_decision" });
}

const cfg = loadConfig(env);

afterEach(() => {
	vi.restoreAllMocks();
});

describe("lead approval race", () => {
	it("two concurrent approvals start exactly one investigation", async () => {
		const host = "race-lead.example";
		const leadId = await newLead(host);
		const wf = fakeWorkflow();
		const [a, b] = await Promise.all([approveLeadAction(wf.env, cfg, leadId, ALICE), approveLeadAction(wf.env, cfg, leadId, BOB)]);
		expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1);
		expect(wf.calls.create).toBe(1);
		const cases = await casesFor(host);
		expect(cases).toHaveLength(1);
		const lead = await getLead(env.DB, leadId);
		expect(lead?.status).toBe("approved");
		expect(lead?.case_id).toBe(cases[0]?.id);
	});

	it("a failed Workflow create marks the case errored and returns the lead to pending", async () => {
		const host = "create-fails.example";
		const leadId = await newLead(host);
		const wf = fakeWorkflow({ createFails: true });
		await expect(startInvestigation(wf.env, cfg, { url: `https://${host}/page`, leadId })).rejects.toThrow("workflow create failed");
		const cases = await casesFor(host);
		expect(cases).toHaveLength(1);
		expect(cases[0]?.status).toBe("errored");
		const lead = await getLead(env.DB, leadId);
		expect(lead?.status).toBe("pending");
		expect(lead?.case_id).toBeNull();

		// The host is not blocked: a retry succeeds.
		const ok = fakeWorkflow();
		const started = await startInvestigation(ok.env, cfg, { url: `https://${host}/page`, leadId });
		expect((await getCase(env.DB, started.caseId))?.status).toBe("collecting");
		expect((await getLead(env.DB, leadId))?.status).toBe("approved");
	});

	it("refuses to start for a lead that is no longer pending", async () => {
		const host = "dismissed-lead.example";
		const leadId = await newLead(host);
		await env.DB.prepare(`UPDATE leads SET status = 'dismissed' WHERE id = ?`).bind(leadId).run();
		const wf = fakeWorkflow();
		await expect(startInvestigation(wf.env, cfg, { url: `https://${host}/`, leadId })).rejects.toBeInstanceOf(CaseInputError);
		expect(wf.calls.create).toBe(0);
	});
});

describe("one open case per host (partial unique index)", () => {
	it("refuses a second open case for a host, but not after the first is closed", async () => {
		const host = "unique-host.example";
		await createCase(env.DB, { id: "case-unique-1", leadId: null, url: `https://${host}/`, host });
		await expect(createCase(env.DB, { id: "case-unique-2", leadId: null, url: `https://${host}/x`, host })).rejects.toThrow(/UNIQUE constraint failed/);

		const wf = fakeWorkflow();
		await expect(startInvestigation(wf.env, cfg, { url: `https://${host}/y`, leadId: null })).rejects.toBeInstanceOf(CaseInputError);
		expect(wf.calls.create).toBe(0);

		await updateCase(env.DB, "case-unique-1", { status: "closed" });
		const started = await startInvestigation(wf.env, cfg, { url: `https://${host}/z`, leadId: null });
		expect(wf.calls.create).toBe(1);
		expect((await casesFor(host)).map((c) => c.status)).toEqual(["closed", "collecting"]);
		expect(started.host).toBe(host);
	});

	it("concurrent manual cases for one host start exactly one Workflow", async () => {
		const host = "manual-race.example";
		const wf = fakeWorkflow();
		const results = await Promise.allSettled([
			startInvestigation(wf.env, cfg, { url: `https://${host}/a`, leadId: null }),
			startInvestigation(wf.env, cfg, { url: `https://${host}/b`, leadId: null }),
		]);
		expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
		const rejected = results.find((r) => r.status === "rejected");
		expect(rejected && rejected.status === "rejected" ? rejected.reason : null).toBeInstanceOf(CaseInputError);
		expect(wf.calls.create).toBe(1);
		expect((await casesFor(host)).filter((c) => c.status === "collecting")).toHaveLength(1);
	});
});

describe("case decision race", () => {
	it("two concurrent decisions deliver exactly one event; decided_by is the winner", async () => {
		const caseId = "case-decide-race";
		await caseAwaitingDecision(caseId, "decide-race.example");
		const wf = fakeWorkflow();
		const [a, b] = await Promise.all([
			decideCaseAction(wf.env, caseId, { action: "decoy" }, ALICE),
			decideCaseAction(wf.env, caseId, { action: "block" }, BOB),
		]);
		expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1);
		expect(wf.calls.sendEvent).toBe(1);
		const winner = a.ok ? ALICE : BOB;
		const loser = a.ok ? b : a;
		expect(loser.summary).toContain("already decided");
		const row = await getCase(env.DB, caseId);
		expect(row?.status).toBe("applying");
		expect(row?.decided_by).toBe(winner.id);
	});

	it("a failed sendEvent releases the claim so someone can decide again", async () => {
		const caseId = "case-decide-fail";
		await caseAwaitingDecision(caseId, "decide-fail.example");
		await expect(decideCaseAction(fakeWorkflow({ sendFails: true }).env, caseId, { action: "none" }, ALICE)).rejects.toThrow("sendEvent failed");
		const row = await getCase(env.DB, caseId);
		expect(row?.status).toBe("awaiting_decision");
		expect(row?.decided_by).toBeNull();
		const retry = await decideCaseAction(fakeWorkflow().env, caseId, { action: "none" }, BOB);
		expect(retry.ok).toBe(true);
		expect((await getCase(env.DB, caseId))?.decided_by).toBe(BOB.id);
	});

	it("never overwrites a case the Workflow already closed", async () => {
		const caseId = "case-decide-closed";
		await caseAwaitingDecision(caseId, "decide-closed.example");
		await updateCase(env.DB, caseId, { status: "closed", decided_by: ALICE.id });
		const wf = fakeWorkflow();
		const r = await decideCaseAction(wf.env, caseId, { action: "block" }, BOB);
		expect(r.ok).toBe(false);
		expect(wf.calls.sendEvent).toBe(0);
		expect((await getCase(env.DB, caseId))?.status).toBe("closed");
	});
});

describe("abuse report double submit", () => {
	async function abuseFixture(caseId: string, host: string) {
		await createCase(env.DB, { id: caseId, leadId: null, url: `https://${host}/`, host });
		await updateCase(env.DB, caseId, { status: "closed", hosted_on_cloudflare: 1 });
		const draft = draftAbuseReport({
			act: "abuse_general",
			caseId,
			cloneUrls: [`https://${host}/`],
			originalUrl: "https://honeypot.automatic-demo.com/",
			sha256: "0".repeat(64),
			capturedAt: new Date().toISOString(),
			rayIds: ["0123456789abcdef"],
		});
		await env.EVIDENCE.put(abuseReportKey(caseId), JSON.stringify(draft));
		const submitEnv = {
			...env,
			ABUSE_REPORTS: "submit",
			CF_API_TOKEN: "test-token",
			ACCOUNT_ID: "test-account",
			ABUSE_REPORTER_JSON: JSON.stringify({ name: "Test Reporter", email: "reporter@example.com" }),
		} as Env;
		return { submitEnv, submitCfg: loadConfig(submitEnv) };
	}

	it("a second concurrent submit is refused and the API is called once", async () => {
		const caseId = "case-abuse-race";
		const { submitEnv, submitCfg } = await abuseFixture(caseId, "abuse-race.example");
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
			await scheduler.wait(30);
			return Response.json({ id: "abuse-report-1" });
		});
		const [a, b] = await Promise.all([
			submitAbuseReportAction(submitEnv, submitCfg, caseId, ALICE),
			submitAbuseReportAction(submitEnv, submitCfg, caseId, BOB),
		]);
		expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1);
		expect((a.ok ? b : a).summary).toContain("already submitted or is in progress");
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		const stored = JSON.parse((await getCase(env.DB, caseId))?.abuse_report ?? "{}") as { result?: { id?: string } };
		expect(stored.result?.id).toBe("abuse-report-1");
	});

	it("a failed submission releases the claim", async () => {
		const caseId = "case-abuse-fail";
		const { submitEnv, submitCfg } = await abuseFixture(caseId, "abuse-fail.example");
		vi.spyOn(globalThis, "fetch").mockImplementation(async () => Response.json({ success: false, errors: [{ code: 1, message: "nope" }] }, { status: 500 }));
		const r = await submitAbuseReportAction(submitEnv, submitCfg, caseId, ALICE);
		expect(r.ok).toBe(false);
		expect((await getCase(env.DB, caseId))?.abuse_report).toBeNull();
	});
});

describe("D1 helpers", () => {
	it("approveFlags and rejectFlags batch and only touch pending rows", async () => {
		const base = { kind: "ip" as const, reason: "trap hit", sourceRef: "0123456789abcdef", pendingTtlDays: 14 };
		for (const ip of ["192.0.2.10", "192.0.2.11", "192.0.2.12"]) await recordPendingFlag(env.DB, { ...base, value: ip });
		const approved = await approveFlags(env.DB, ["ip:192.0.2.10", "ip:192.0.2.11", "ip:192.0.2.99"], { ttlDays: 3, action: "block" });
		expect(approved.map((f) => f.indicator).sort()).toEqual(["ip:192.0.2.10", "ip:192.0.2.11"]);
		expect(approved.every((f) => f.status === "active" && f.action === "block")).toBe(true);
		// Already active: not approved again, not rejected.
		expect(await approveFlags(env.DB, ["ip:192.0.2.10"], { ttlDays: 3 })).toEqual([]);
		expect(await rejectFlags(env.DB, ["ip:192.0.2.10", "ip:192.0.2.12", "ip:192.0.2.99"])).toBe(1);
		expect(await approveFlags(env.DB, [], { ttlDays: 3 })).toEqual([]);
		expect(await rejectFlags(env.DB, [])).toBe(0);
	});

	it("approveFlags handles more indicators than one batch chunk", async () => {
		const ips = Array.from({ length: 130 }, (_, i) => `198.18.${Math.floor(i / 250)}.${i + 1}`);
		const base = { kind: "ip" as const, reason: "trap hit", sourceRef: "0123456789abcdef", pendingTtlDays: 14 };
		for (const ip of ips) await recordPendingFlag(env.DB, { ...base, value: ip });
		const approved = await approveFlags(env.DB, ips.map((ip) => `ip:${ip}`), { ttlDays: 1 });
		expect(approved).toHaveLength(130);
	});

	it("upsertActiveFlag returns the stored row", async () => {
		const row = await upsertActiveFlag(env.DB, { kind: "ip", value: "192.0.2.50", action: "decoy", reason: "manual", source: "manual", sourceRef: null, ttlDays: 2 });
		expect(row.indicator).toBe("ip:192.0.2.50");
		expect(row.status).toBe("active");
		const again = await upsertActiveFlag(env.DB, { kind: "ip", value: "192.0.2.50", action: "block", reason: "manual 2", source: "manual", sourceRef: null, ttlDays: 2 });
		expect(again.action).toBe("block");
		expect(again.reason).toBe("manual 2");
	});

	it("updateCase rejects columns that are not on the allowlist", async () => {
		await createCase(env.DB, { id: "case-allowlist", leadId: null, url: "https://allowlist.example/", host: "allowlist.example" });
		await expect(updateCase(env.DB, "case-allowlist", { ["host; DROP TABLE cases; --"]: "x" } as never)).rejects.toThrow("not updatable");
		await updateCase(env.DB, "case-allowlist", { status: "closed", report_key: undefined });
		expect((await getCase(env.DB, "case-allowlist"))?.status).toBe("closed");
	});
});
