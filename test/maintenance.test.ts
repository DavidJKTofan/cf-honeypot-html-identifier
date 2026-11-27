/**
 * End-to-end MaintenanceWorkflow runs (Vitest Workflows test APIs, L14): expiry, a WAF removal
 * that fails, reconcile, lead intake and the pending-flag digest. Steps that need the network
 * (Analytics SQL, the Lists API) are mocked; D1 is the local test binding. Remember that
 * `mockStepResult(step, null)` still runs the real step: mock with a non-null value to skip it.
 * https://developers.cloudflare.com/workers/testing/vitest-integration/test-apis/#workflows
 */
import { createExecutionContext, introspectWorkflow, introspectWorkflowInstance } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { pendingFlagDigest } from "../src/approvals/digest";
import type { WafRemoval } from "../src/approvals/enforce";
import { handleAdmin } from "../src/admin/router";
import { loadConfig } from "../src/core/config";
import { nowSec } from "../src/core/util";
import { flagsMessage } from "../src/notify/discord/messages";
import { createCase, getFlag, indicatorFor, insertCaseTokens, listLeads, updateCase, type CaseStatus, type FlagAction, type FlagStatus } from "../src/storage/d1";

type Modifier = Parameters<Parameters<Awaited<ReturnType<typeof introspectWorkflowInstance>>["modify"]>[0]>[0];

interface Summary {
	expiredFlags: number;
	expiredBlockedIps: number;
	wafRemoval: { status: string; removed: number; failed: number };
	purged: { deleted: number; kept: number };
	reconcile: unknown;
	staleLeads: number;
	hotlinkLeads: number;
	brandLeads: number | string;
	flagDigest: string;
}

const PAST = nowSec() - 3600;
const FUTURE = nowSec() + 86_400;

async function insertFlag(ip: string, f: { action: FlagAction; status: FlagStatus; expiresAt: number; hits?: number }): Promise<void> {
	const now = nowSec();
	await env.DB.prepare(
		`INSERT INTO flags (indicator, kind, action, status, reason, source, source_ref, created_at, updated_at, expires_at, hits)
		 VALUES (?, 'ip', ?, ?, 'test', 'trap', '0000000000000000', ?, ?, ?, ?)`,
	)
		.bind(indicatorFor("ip", ip), f.action, f.status, now, now, f.expiresAt, f.hits ?? 1)
		.run();
}

async function caseWithToken(id: string, host: string, status: CaseStatus, ip: string): Promise<void> {
	await createCase(env.DB, { id, leadId: null, url: `https://${host}/`, host });
	await updateCase(env.DB, id, { status });
	await insertCaseTokens(env.DB, [{ case_id: id, ray_id: `${id.length.toString(16).padStart(4, "0")}${"0".repeat(12)}`, ip, asn: 64496, country: "DE", issued_at: PAST, carrier: "meta" }]);
}

/**
 * Start one MaintenanceWorkflow instance, let `extra` add mocks, and return its output.
 * Analytics SQL has no local implementation, so the foreign Referer hosts are always mocked.
 */
async function runMaintenance(id: string, extra: (m: Modifier) => Promise<void> = async () => {}, refererHosts: string[] = []): Promise<Summary> {
	await using instance = await introspectWorkflowInstance(env.MAINTENANCE, id);
	await instance.modify(async (m) => {
		await m.disableSleeps();
		await m.disableRetryDelays();
		await m.mockStepResult({ name: "find foreign referer hosts" }, refererHosts);
		await extra(m);
	});
	await env.MAINTENANCE.create({ id });
	await instance.waitForStatus("complete");
	return (await instance.getOutput()) as Summary;
}

beforeEach(async () => {
	await env.DB.batch([
		env.DB.prepare("DELETE FROM flags"),
		env.DB.prepare("DELETE FROM leads"),
		env.DB.prepare("DELETE FROM case_tokens"),
		env.DB.prepare("DELETE FROM cases"),
	]);
});

describe("MaintenanceWorkflow: expired flags (H1)", () => {
	it("deletes expired flags of every kind, keeps unexpired ones, and purges stale leads", async () => {
		await insertFlag("198.51.100.1", { action: "decoy", status: "pending", expiresAt: PAST });
		await insertFlag("198.51.100.2", { action: "decoy", status: "active", expiresAt: PAST });
		await insertFlag("198.51.100.3", { action: "decoy", status: "rejected", expiresAt: PAST });
		// An expired block: without a WAF list configured (tests), the real removal step reports "skipped".
		await insertFlag("198.51.100.4", { action: "block", status: "active", expiresAt: PAST });
		await insertFlag("198.51.100.5", { action: "block", status: "active", expiresAt: FUTURE });
		await insertFlag("198.51.100.6", { action: "decoy", status: "pending", expiresAt: FUTURE });
		await env.DB.prepare("INSERT INTO leads (host, source, status, first_seen, last_seen) VALUES ('stale.example', 'referer', 'pending', 1, 1)").run();

		const out = await runMaintenance("maint-expire");
		expect(out).toMatchObject({
			expiredFlags: 4,
			expiredBlockedIps: 1,
			wafRemoval: { status: "skipped", removed: 1, failed: 0 },
			purged: { deleted: 4, kept: 0 },
			staleLeads: 1,
		});
		for (const ip of ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"]) expect(await getFlag(env.DB, `ip:${ip}`)).toBeNull();
		expect(await getFlag(env.DB, "ip:198.51.100.5")).toMatchObject({ status: "active", action: "block" });
		expect(await getFlag(env.DB, "ip:198.51.100.6")).toMatchObject({ status: "pending" });
		expect(await listLeads(env.DB, null)).toHaveLength(0);
	});

	it("keeps the row of an expired block whose WAF list item could not be removed", async () => {
		await insertFlag("198.51.100.11", { action: "block", status: "active", expiresAt: PAST }); // removal fails
		await insertFlag("198.51.100.12", { action: "block", status: "active", expiresAt: PAST }); // removed
		await insertFlag("198.51.100.13", { action: "decoy", status: "pending", expiresAt: PAST }); // never in the list
		const removal: WafRemoval = { status: "error", removed: ["198.51.100.12"], failed: ["198.51.100.11"], error: "lists api 500" };

		await using instance = await introspectWorkflowInstance(env.MAINTENANCE, "maint-waf-partial");
		await instance.modify(async (m) => {
			await m.disableSleeps();
			await m.mockStepResult({ name: "find foreign referer hosts" }, []);
			await m.mockStepResult({ name: "remove expired WAF list items" }, removal);
		});
		await env.MAINTENANCE.create({ id: "maint-waf-partial" });
		const found = (await instance.waitForStepResult({ name: "find expired flags" })) as { blockIps: string[]; indicators: string[] };
		expect([...found.blockIps].sort()).toEqual(["198.51.100.11", "198.51.100.12"]);
		// Only active blocks are listed: the expired pending row has no list item and is deleted by the stale steps.
		expect(found.indicators).toHaveLength(2);
		await instance.waitForStatus("complete");
		expect(await instance.getOutput()).toMatchObject({ wafRemoval: { status: "error", removed: 1, failed: 1 }, purged: { deleted: 2, kept: 1 } });
		expect(await getFlag(env.DB, "ip:198.51.100.11")).toMatchObject({ action: "block", status: "active" });
		expect(await getFlag(env.DB, "ip:198.51.100.12")).toBeNull();
		expect(await getFlag(env.DB, "ip:198.51.100.13")).toBeNull();
	});

	it("keeps every expired block row when the removal step fails on every attempt, and still completes", async () => {
		await insertFlag("198.51.100.21", { action: "block", status: "active", expiresAt: PAST });
		await insertFlag("198.51.100.22", { action: "block", status: "active", expiresAt: PAST });
		await insertFlag("198.51.100.23", { action: "decoy", status: "active", expiresAt: PAST });
		const out = await runMaintenance("maint-waf-down", async (m) => {
			await m.mockStepError({ name: "remove expired WAF list items" }, new Error("lists api down (test)"));
		});
		expect(out).toMatchObject({ wafRemoval: { status: "error", removed: 0, failed: 2 }, purged: { deleted: 1, kept: 2 } });
		expect(await getFlag(env.DB, "ip:198.51.100.21")).not.toBeNull();
		expect(await getFlag(env.DB, "ip:198.51.100.22")).not.toBeNull();
		expect(await getFlag(env.DB, "ip:198.51.100.23")).toBeNull();
	});
});

/**
 * Seed `count` expired flags in one statement (a recursive CTE), the way a distributed crawl
 * leaves them behind: unique indicators from `prefix` plus a hex counter.
 */
async function seedExpired(count: number, f: { prefix: string; kind: "ip" | "ja4"; action: FlagAction; status: FlagStatus }): Promise<void> {
	await env.DB.prepare(
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
		 INSERT INTO flags (indicator, kind, action, status, reason, source, source_ref, created_at, updated_at, expires_at, hits)
		 SELECT printf('%s%x', ?2, i), ?3, ?4, ?5, 'trap hit (bot score 1)', 'trap', '0000000000000000', ?6, ?6, ?6, 1 FROM n`,
	)
		.bind(count, f.prefix, f.kind, f.action, f.status, PAST)
		.run();
}

describe("MaintenanceWorkflow: expired-flag backlog (C3)", () => {
	it("drains a backlog far larger than one batch, survives a transient D1 error, and never touches an IP block whose list item is still there", async () => {
		// 2,500 expired rows without a WAF list item: pending trap flags (IPv6, as residential proxies
		// rotate them), rejected ones, expired decoys and expired JA4 blocks (enforced by the Worker only).
		await seedExpired(2000, { prefix: "ip:2001:db8::", kind: "ip", action: "decoy", status: "pending" });
		await seedExpired(300, { prefix: "ip:2001:db8:1::", kind: "ip", action: "decoy", status: "rejected" });
		await seedExpired(150, { prefix: "ip:2001:db8:2::", kind: "ip", action: "decoy", status: "active" });
		await seedExpired(50, { prefix: "ja4:t13d1516h2_8daaf6152771_", kind: "ja4", action: "block", status: "active" });
		// An expired IP block whose list removal keeps failing: it must survive every stale chunk.
		await insertFlag("203.0.113.50", { action: "block", status: "active", expiresAt: PAST });
		// Unexpired rows of each kind stay.
		await insertFlag("203.0.113.51", { action: "decoy", status: "pending", expiresAt: FUTURE });
		await insertFlag("203.0.113.52", { action: "decoy", status: "active", expiresAt: FUTURE });
		await insertFlag("203.0.113.53", { action: "block", status: "active", expiresAt: FUTURE });

		await using instance = await introspectWorkflowInstance(env.MAINTENANCE, "maint-backlog");
		await instance.modify(async (m) => {
			await m.disableSleeps();
			await m.disableRetryDelays();
			await m.mockStepResult({ name: "find foreign referer hosts" }, []);
			await m.mockStepError({ name: "remove expired WAF list items" }, new Error("lists api down (test)"));
			// The transient D1 error the retry guide names: the retried chunk must not double count.
			await m.mockStepError({ name: "delete stale flags #2" }, new Error("D1_ERROR: Network connection lost."), 1);
		});
		await env.MAINTENANCE.create({ id: "maint-backlog" });

		expect(await instance.waitForStepResult({ name: "delete stale flags #1" })).toBe(1000);
		expect(await instance.waitForStepResult({ name: "delete stale flags #2" })).toBe(1000);
		expect(await instance.waitForStepResult({ name: "delete stale flags #3" })).toBe(500);
		await instance.waitForStatus("complete");
		expect(await instance.getOutput()).toMatchObject({
			expiredFlags: 2501,
			expiredBlockedIps: 1,
			wafRemoval: { status: "error", removed: 0, failed: 1 },
			purged: { deleted: 2500, kept: 1 },
		});

		const left = await env.DB.prepare("SELECT indicator FROM flags ORDER BY indicator").all<{ indicator: string }>();
		expect(left.results.map((r) => r.indicator)).toEqual(["ip:203.0.113.50", "ip:203.0.113.51", "ip:203.0.113.52", "ip:203.0.113.53"]);
		expect(await getFlag(env.DB, "ip:203.0.113.50")).toMatchObject({ action: "block", status: "active" });
	});
});

describe("MaintenanceWorkflow: reconcile", () => {
	it("is skipped without a WAF list (the real step runs)", async () => {
		const out = await runMaintenance("maint-reconcile-skip");
		expect(out.reconcile).toMatchObject({ status: "skipped", listed: 0, removed: 0, added: 0 });
	});

	it("reports a failed reconcile and still runs the steps after it", async () => {
		await insertFlag("198.51.100.31", { action: "decoy", status: "pending", expiresAt: FUTURE });
		const out = await runMaintenance("maint-reconcile-fail", async (m) => {
			await m.mockStepError({ name: "reconcile WAF list" }, new Error("list read failed (test)"));
		});
		expect(out.reconcile).toBe("error: list read failed (test)");
		expect(out.staleLeads).toBe(0);
		expect(out.flagDigest).toContain("1 pending");
	});
});

describe("MaintenanceWorkflow: lead intake", () => {
	it("turns foreign Referer hosts into pending leads, one step per host; one failing host doesn't stop the others", async () => {
		const out = await runMaintenance(
			"maint-referer",
			async (m) => {
				await m.mockStepError({ name: "referer lead #2: hotlink-b.example" }, new Error("d1 down (test)"));
			},
			["hotlink-a.example", "hotlink-b.example", "hotlink-c.example"],
		);
		expect(out.hotlinkLeads).toBe(2);
		expect(out.brandLeads).toBe("skipped: CF_API_TOKEN not configured");
		const leads = await listLeads(env.DB, "pending");
		expect(leads.map((l) => l.host).sort()).toEqual(["hotlink-a.example", "hotlink-c.example"]);
		expect(leads.every((l) => l.source === "referer")).toBe(true);
	});
});

describe("MaintenanceWorkflow: pending-flag digest", () => {
	it("says so when nothing is pending", async () => {
		expect((await runMaintenance("maint-digest-none")).flagDigest).toBe("none pending");
	});

	it("counts pending flags whose IP is also part of an open case (digest context)", async () => {
		await insertFlag("203.0.113.41", { action: "decoy", status: "pending", expiresAt: FUTURE, hits: 9 });
		await insertFlag("203.0.113.42", { action: "decoy", status: "pending", expiresAt: FUTURE, hits: 5 });
		await caseWithToken("case-digest-open", "digest-open.example", "awaiting_decision", "203.0.113.41");
		await caseWithToken("case-digest-closed", "digest-closed.example", "closed", "203.0.113.42");
		// No notifier in tests: the digest is built, then "not sent".
		expect((await runMaintenance("maint-digest-context")).flagDigest).toBe("not sent (2 pending, 1 also in an open case; notifier disabled?)");
	});
});

describe("Digest context", () => {
	it("annotates only IPs in an open case, with the newest open case", async () => {
		await insertFlag("203.0.113.51", { action: "decoy", status: "pending", expiresAt: FUTURE, hits: 3 });
		await insertFlag("203.0.113.52", { action: "decoy", status: "pending", expiresAt: FUTURE, hits: 2 });
		await insertFlag("203.0.113.53", { action: "decoy", status: "pending", expiresAt: FUTURE, hits: 1 });
		await caseWithToken("case-ctx-open", "ctx-open.example", "applying", "203.0.113.51");
		await caseWithToken("case-ctx-expired", "ctx-expired.example", "expired", "203.0.113.52");
		const digest = await pendingFlagDigest(env.DB, 5);
		expect(digest.total).toBe(3);
		expect(digest.inOpenCase).toBe(1);
		expect(digest.flags.map((f) => [f.indicator, f.openCase?.id ?? null])).toEqual([
			["ip:203.0.113.51", "case-ctx-open"],
			["ip:203.0.113.52", null],
			["ip:203.0.113.53", null],
		]);
	});

	it("the digest message tells approvers to decide in the case, and keeps the buttons", () => {
		const flags = [
			{ indicator: "ip:203.0.113.61", reason: "trap hit", hits: 4, createdAt: 1_700_000_000, openCase: { id: "case-msg-1", status: "awaiting_decision" } },
			{ indicator: "ip:203.0.113.62", reason: "trap hit", hits: 1, createdAt: 1_700_000_000 },
		];
		const interactive = flagsMessage(flags, 2, true);
		const fields = (interactive.embeds[0]?.fields ?? []) as { name: string; value: string }[];
		expect(fields[0]?.value).toContain("Also in case `case-msg-1`");
		expect(fields[0]?.value).toContain("decide there");
		expect(fields[1]?.value).not.toContain("Also in case");
		expect(interactive.components).toHaveLength(2);
		const plain = flagsMessage(flags, 2, false);
		expect(((plain.embeds[0]?.fields ?? []) as { value: string }[])[0]?.value).toContain("case-status case-msg-1");
	});
});

describe("POST /maintenance/run", () => {
	it("starts one MaintenanceWorkflow, which completes", async () => {
		await using introspector = await introspectWorkflow(env.MAINTENANCE);
		await introspector.modifyAll(async (m) => {
			await m.disableSleeps();
			await m.mockStepResult({ name: "find foreign referer hosts" }, []);
		});
		const res = await handleAdmin(
			new Request("https://honeypot.automatic-demo.com/__hp/maintenance/run", { method: "POST", headers: { authorization: "Bearer test-admin-token" } }),
			env,
			createExecutionContext(),
			loadConfig(env),
		);
		expect(res.status).toBe(202);
		const { instance: id } = (await res.json()) as { instance: string };
		expect(id).toMatch(/^maint-manual-/);
		const instances = await introspector.get();
		expect(instances).toHaveLength(1);
		await instances[0]?.waitForStatus("complete");
		expect(await instances[0]?.getOutput()).toMatchObject({ expiredFlags: 0, flagDigest: "none pending" });
	});
});
