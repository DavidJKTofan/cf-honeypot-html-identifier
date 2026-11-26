/**
 * End-to-end InvestigateWorkflow runs (Vitest Workflows test APIs): network-bound steps are
 * mocked, D1 and R2 are the local test bindings.
 * https://developers.cloudflare.com/workers/testing/vitest-integration/test-apis/#workflows
 */
import { introspectWorkflowInstance } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { InvestigateParams } from "../src/approvals/cases";
import { nowSec } from "../src/core/util";
import type { Fingerprint } from "../src/identity/fingerprint";
import { loadSealingKey, sealToken } from "../src/identity/token";
import { claimLead, createCase, getCase, getFlag, getLead, setCaseStatusIf, updateCase, upsertActiveFlag, upsertLead } from "../src/storage/d1";
import { MAX_CASE_TOKENS } from "../src/workflows/evidence";
import type { CaptureResult, DecodeResult, HostingSummary, TokenEvidence } from "../src/workflows/types";

const ISSUED = nowSec() - 86_400; // an old scrape: no Analytics Engine ingestion wait

function fp(ip: string, i = 0): Fingerprint {
	return {
		issuedAt: ISSUED + i,
		ip,
		asn: 64496,
		country: "DE",
		colo: "FRA",
		botScore: 1,
		verifiedBot: false,
		jsDetectionPassed: false,
		botManagement: true,
		rayId: i.toString(16).padStart(16, "0"),
	};
}

function tokenEvidence(ip: string): TokenEvidence {
	return { carrier: "meta", issuedAtIso: new Date(ISSUED * 1000).toISOString(), fingerprint: fp(ip), viaCloudflare: false, source: "capture", secondsBeforeCapture: 86_400 };
}

const HOSTING: HostingSummary = { ips: ["192.0.2.80"], onCloudflare: false, error: null, abuseDraftKey: null, abuseDraftSkipped: null };

async function startCase(caseId: string, host: string, leadId: number | null = null): Promise<InvestigateParams> {
	await createCase(env.DB, { id: caseId, leadId, url: `https://${host}/`, host });
	return { caseId, url: `https://${host}/`, host, leadId };
}

/** Capture result whose snapshot is `html`, stored in the local R2 bucket. */
async function capture(caseId: string, html: string): Promise<CaptureResult> {
	const key = `cases/${caseId}/snapshot.html`;
	await env.EVIDENCE.put(key, html);
	return { key, sha256: "0".repeat(64), status: 200, finalUrl: "", bytes: html.length, truncated: false, fetchedAt: new Date().toISOString(), headers: {} };
}

describe("InvestigateWorkflow: decision timing (H2)", () => {
	it("an undecided case expires", async () => {
		const caseId = "case-wf-expire";
		const params = await startCase(caseId, "wf-expire.example");
		await using instance = await introspectWorkflowInstance(env.INVESTIGATE, caseId);
		await instance.modify(async (m) => {
			await m.disableSleeps();
			await m.mockStepResult({ name: "capture suspected copy" }, await capture(caseId, "<p>x</p>"));
			await m.mockStepResult({ name: "extract and open tokens" }, { beaconScript: true, trapLink: true, candidates: 1, tokens: [tokenEvidence("203.0.113.70")] } satisfies DecodeResult);
			await m.mockStepResult({ name: "enrich from analytics engine" }, {});
			await m.mockStepResult({ name: "cloudflare hosting check" }, HOSTING);
			await m.forceEventTimeout({ name: "wait for human decision" });
		});
		await env.INVESTIGATE.create({ id: caseId, params });
		await instance.waitForStatus("complete");
		expect(await instance.getOutput()).toMatchObject({ status: "expired" });
		expect((await getCase(env.DB, caseId))?.status).toBe("expired");
	});

	it("a decision claimed as the wait times out is applied, not overwritten as expired", async () => {
		const caseId = "case-wf-late";
		const params = await startCase(caseId, "wf-late.example");
		await using instance = await introspectWorkflowInstance(env.INVESTIGATE, caseId);
		await instance.modify(async (m) => {
			await m.disableSleeps();
			await m.mockStepResult({ name: "capture suspected copy" }, await capture(caseId, "<p>x</p>"));
			await m.mockStepResult({ name: "extract and open tokens" }, { beaconScript: true, trapLink: true, candidates: 1, tokens: [tokenEvidence("203.0.113.71")] } satisfies DecodeResult);
			await m.mockStepResult({ name: "enrich from analytics engine" }, {});
			await m.mockStepResult({ name: "cloudflare hosting check" }, HOSTING);
			// The approver's claim (decideCaseAction) lands as the 7-day wait times out: the case is
			// `applying` and the event is buffered for the instance.
			await m.mockStepResult({ name: "write evidence report" }, "mocked"); // skips the real step, which would set awaiting_decision
			await m.forceEventTimeout({ name: "wait for human decision" });
			await m.mockEvent({ type: "decision", payload: { action: "decoy", ttlDays: 2, actor: "discord:333333333333333333" } });
		});
		await updateCase(env.DB, caseId, { status: "applying", decided_by: "discord:333333333333333333" });
		await env.INVESTIGATE.create({ id: caseId, params });
		await instance.waitForStatus("complete");
		expect(await instance.getOutput()).toMatchObject({ status: "closed", applied: { action: "decoy", indicators: ["ip:203.0.113.71"] } });
		expect(await getCase(env.DB, caseId)).toMatchObject({ status: "closed", decided_by: "discord:333333333333333333" });
		expect(await getFlag(env.DB, "ip:203.0.113.71")).toMatchObject({ status: "active", action: "decoy" });
	});

	it("setCaseStatusIf only moves a case out of the expected states", async () => {
		await startCase("case-cond", "cond.example");
		expect(await setCaseStatusIf(env.DB, "case-cond", ["awaiting_decision"], "expired")).toEqual({ changed: false, status: "collecting" });
		await updateCase(env.DB, "case-cond", { status: "applying" });
		expect(await setCaseStatusIf(env.DB, "case-cond", ["applying"], "closed", { decided_by: "admin" })).toEqual({ changed: true, status: "closed" });
		expect((await getCase(env.DB, "case-cond"))?.decided_by).toBe("admin");
		expect(await setCaseStatusIf(env.DB, "case-missing", ["applying"], "closed")).toEqual({ changed: false, status: null });
	});
});

describe("InvestigateWorkflow: enforcement (H1)", () => {
	it("a decoy decision for a blocked IP removes its WAF list item", async () => {
		const caseId = "case-wf-downgrade";
		const params = await startCase(caseId, "wf-downgrade.example");
		await upsertActiveFlag(env.DB, { kind: "ip", value: "203.0.113.72", action: "block", reason: "manual", source: "manual", sourceRef: null, ttlDays: 7 });
		await using instance = await introspectWorkflowInstance(env.INVESTIGATE, caseId);
		await instance.modify(async (m) => {
			await m.disableSleeps();
			await m.mockStepResult({ name: "capture suspected copy" }, await capture(caseId, "<p>x</p>"));
			await m.mockStepResult({ name: "extract and open tokens" }, { beaconScript: true, trapLink: true, candidates: 1, tokens: [tokenEvidence("203.0.113.72")] } satisfies DecodeResult);
			await m.mockStepResult({ name: "enrich from analytics engine" }, {});
			await m.mockStepResult({ name: "cloudflare hosting check" }, HOSTING);
			await m.mockEvent({ type: "decision", payload: { action: "decoy" } });
		});
		await env.INVESTIGATE.create({ id: caseId, params });
		// No CF_API_TOKEN in tests, so the removal reports "skipped": what matters is that it runs.
		expect(await instance.waitForStepResult({ name: "remove downgraded blocks from WAF list" })).toBe("skipped");
		await instance.waitForStatus("complete");
		expect(await getFlag(env.DB, "ip:203.0.113.72")).toMatchObject({ action: "decoy", status: "active" });
	});
});

describe("InvestigateWorkflow: evidence bounds (N1, N2)", () => {
	it("records at most MAX_CASE_TOKENS valid tokens from a page stuffed with genuine ones", async () => {
		const caseId = "case-wf-stuffed";
		const params = await startCase(caseId, "wf-stuffed.example");
		const key = await loadSealingKey(env);
		const tokens = await Promise.all(Array.from({ length: MAX_CASE_TOKENS + 10 }, (_, i) => sealToken(fp(`198.18.0.${i + 1}`, i), key)));
		const html = `<html><body>${tokens.map((t) => `<i data-t="${t}"></i>`).join("")}</body></html>`;
		await using instance = await introspectWorkflowInstance(env.INVESTIGATE, caseId);
		await instance.modify(async (m) => {
			await m.disableSleeps();
			await m.mockStepResult({ name: "capture suspected copy" }, await capture(caseId, html));
			await m.mockStepResult({ name: "enrich from analytics engine" }, {});
			await m.mockStepResult({ name: "cloudflare hosting check" }, HOSTING);
			await m.forceEventTimeout({ name: "wait for human decision" });
		});
		await env.INVESTIGATE.create({ id: caseId, params });
		const decoded = (await instance.waitForStepResult({ name: "extract and open tokens" })) as DecodeResult;
		expect(decoded.tokens).toHaveLength(MAX_CASE_TOKENS);
		expect(decoded.omittedTokens).toBe(10);
		// The earliest fetches and the newest are kept.
		expect(decoded.tokens.map((t) => t.fingerprint.ip)).toContain("198.18.0.1");
		expect(decoded.tokens.map((t) => t.fingerprint.ip)).toContain(`198.18.0.${MAX_CASE_TOKENS + 10}`);
		await instance.waitForStatus("complete");
		expect((await getCase(env.DB, caseId))?.token_count).toBe(MAX_CASE_TOKENS);
	});

	it("never uses a lead's beacon token as evidence against another host", async () => {
		const lead = await upsertLead(env.DB, {
			host: "wf-lead-host.example",
			sampleUrl: null,
			source: "beacon",
			tokenRay: "0000000000000000",
			token: await sealToken(fp("203.0.113.73"), await loadSealingKey(env)),
			tokenIp: "203.0.113.73",
		});
		const leadId = lead!.lead.id;
		const caseId = "case-wf-otherhost";
		const params = await startCase(caseId, "wf-other-host.example", leadId);
		await using instance = await introspectWorkflowInstance(env.INVESTIGATE, caseId);
		await instance.modify(async (m) => {
			await m.disableSleeps();
			await m.mockStepResult({ name: "capture suspected copy" }, await capture(caseId, "<html><body>no token here</body></html>"));
		});
		await env.INVESTIGATE.create({ id: caseId, params });
		await instance.waitForStatus("complete");
		expect(await instance.getOutput()).toMatchObject({ status: "no_evidence" });
	});
});

describe("InvestigateWorkflow: errors (N6)", () => {
	it("an errored investigation puts its lead back to pending", async () => {
		const lead = await upsertLead(env.DB, { host: "wf-error.example", sampleUrl: null, source: "beacon", tokenRay: "0000000000000001" });
		const leadId = lead!.lead.id;
		expect(await claimLead(env.DB, leadId)).toBe(true);
		const caseId = "case-wf-error";
		const params = await startCase(caseId, "wf-error.example", leadId);
		await env.DB.prepare(`UPDATE leads SET case_id = ? WHERE id = ?`).bind(caseId, leadId).run();
		await using instance = await introspectWorkflowInstance(env.INVESTIGATE, caseId);
		await instance.modify(async (m) => {
			await m.disableRetryDelays();
			await m.mockStepError({ name: "capture suspected copy" }, new Error("capture failed (test)"));
		});
		await env.INVESTIGATE.create({ id: caseId, params });
		await instance.waitForStatus("errored");
		expect((await getCase(env.DB, caseId))?.status).toBe("errored");
		expect(await getLead(env.DB, leadId)).toMatchObject({ status: "pending", case_id: null });
	});
});
