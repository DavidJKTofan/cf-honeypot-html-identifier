/**
 * D1 write retries on human-driven request paths (L3): only the transient errors from the D1
 * guide, jittered exponential backoff, at most 5 attempts, never for reads.
 * https://developers.cloudflare.com/d1/best-practices/retry-queries/
 */
import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { handleAdmin } from "../src/admin/router";
import { loadConfig } from "../src/core/config";
import { claimLead, getLead, upsertActiveFlag, upsertLead } from "../src/storage/d1";
import { isRetryableD1Error, isWriteSql, retryD1, withD1WriteRetries } from "../src/storage/retry";
import { flakyD1, NETWORK_LOST } from "./flaky-d1";

const noSleep = { sleep: async () => {} };

describe("retryD1", () => {
	it("retries only the transient errors the D1 guide names", () => {
		expect(isRetryableD1Error(new Error(NETWORK_LOST))).toBe(true);
		expect(isRetryableD1Error(new Error("D1_ERROR: Internal error while starting up D1 DB storage caused object to be reset."))).toBe(true);
		expect(isRetryableD1Error(new Error("D1 DB reset because its code was updated."))).toBe(true);
		expect(isRetryableD1Error(new Error("D1_ERROR: UNIQUE constraint failed: cases.host"))).toBe(false);
		expect(isRetryableD1Error(new Error("D1 DB is overloaded. Too many requests queued."))).toBe(false);
	});

	it("succeeds after transient failures, with growing jittered delays", async () => {
		let calls = 0;
		const sleeps: number[] = [];
		const result = await retryD1(
			async () => {
				if (++calls < 4) throw new Error(NETWORK_LOST);
				return "ok";
			},
			{ sleep: async (ms) => void sleeps.push(ms), baseDelayMs: 100, maxDelayMs: 2_000 },
		);
		expect(result).toBe("ok");
		expect(calls).toBe(4);
		expect(sleeps).toHaveLength(3);
		// Equal jitter: attempt n waits between half and all of base * 2^(n-1).
		sleeps.forEach((ms, i) => {
			expect(ms).toBeGreaterThanOrEqual((100 * 2 ** i) / 2);
			expect(ms).toBeLessThanOrEqual(100 * 2 ** i);
		});
	});

	it("gives up after 5 attempts and rethrows", async () => {
		let calls = 0;
		await expect(
			retryD1(async () => {
				calls++;
				throw new Error(NETWORK_LOST);
			}, noSleep),
		).rejects.toThrow("Network connection lost");
		expect(calls).toBe(5);
		// A larger maxAttempts is capped at the guide's 5.
		calls = 0;
		await expect(retryD1(async () => (calls++, Promise.reject(new Error(NETWORK_LOST))), { ...noSleep, maxAttempts: 9 })).rejects.toThrow();
		expect(calls).toBe(5);
	});

	it("never retries other errors", async () => {
		let calls = 0;
		await expect(
			retryD1(async () => {
				calls++;
				throw new Error("UNIQUE constraint failed");
			}, noSleep),
		).rejects.toThrow("UNIQUE");
		expect(calls).toBe(1);
	});
});

describe("withD1WriteRetries", () => {
	it("classifies statements: reads are never retried, unknown statements count as writes", () => {
		expect(isWriteSql("SELECT * FROM flags")).toBe(false);
		expect(isWriteSql("  select 1")).toBe(false);
		expect(isWriteSql("WITH x AS (SELECT 1) SELECT * FROM x")).toBe(false);
		expect(isWriteSql("WITH x AS (SELECT 1) DELETE FROM flags")).toBe(true);
		expect(isWriteSql("UPDATE leads SET status = 'approved' WHERE id = ? AND status = 'pending'")).toBe(true);
		expect(isWriteSql("INSERT INTO flags VALUES (?)")).toBe(true);
		expect(isWriteSql("DELETE FROM flags WHERE indicator = ? RETURNING *")).toBe(true);
	});

	it("retries a claim and keeps meta.changes, so the claim still reports who won", async () => {
		const lead = await upsertLead(env.DB, { host: "retry-claim.example", sampleUrl: null, source: "manual", tokenRay: null });
		const flaky = flakyD1(env.DB, 2);
		const db = withD1WriteRetries(flaky.db, noSleep);
		expect(await claimLead(db, lead!.lead.id)).toBe(true);
		expect(flaky.state.thrown).toBe(2);
		expect((await getLead(env.DB, lead!.lead.id))?.status).toBe("approved");
		// A second claim is refused (changes = 0), not retried into a false success.
		expect(await claimLead(db, lead!.lead.id)).toBe(false);
	});

	it("retries a batch that writes, as one transaction", async () => {
		const flaky = flakyD1(env.DB, 1);
		const db = withD1WriteRetries(flaky.db, noSleep);
		const { row, previous } = await upsertActiveFlag(db, { kind: "ip", value: "192.0.2.201", action: "decoy", reason: "retry", source: "manual", sourceRef: null, ttlDays: 1 });
		expect(row.indicator).toBe("ip:192.0.2.201");
		expect(previous).toBeNull();
		expect(flaky.state.thrown).toBe(1);
	});

	it("does not retry reads (D1 already does)", async () => {
		let reads = 0;
		const failingReads = new Proxy(env.DB, {
			get(target, prop) {
				if (prop === "prepare") {
					return (sql: string) => ({
						bind: () => ({
							first: async () => {
								reads++;
								throw new Error(NETWORK_LOST);
							},
						}),
						sql,
					});
				}
				return Reflect.get(target, prop, target);
			},
		}) as D1Database;
		const db = withD1WriteRetries(failingReads, noSleep);
		await expect(db.prepare("SELECT * FROM leads WHERE id = ?").bind(1).first()).rejects.toThrow();
		expect(reads).toBe(1);
	});

	it("stops after 5 attempts on a write that keeps failing", async () => {
		const flaky = flakyD1(env.DB, 10);
		const db = withD1WriteRetries(flaky.db, noSleep);
		await expect(claimLead(db, 1)).rejects.toThrow("Network connection lost");
		expect(flaky.state.writes).toBe(5);
	});
});

describe("human-driven paths retry their writes", () => {
	const cfg = loadConfig(env);

	it("the admin API survives transient write errors (dismiss a lead)", async () => {
		const lead = await upsertLead(env.DB, { host: "retry-admin.example", sampleUrl: null, source: "manual", tokenRay: null });
		const flaky = flakyD1(env.DB, 2);
		const flakyEnv = { ...env, DB: flaky.db } as Env;
		const res = await handleAdmin(
			new Request(`https://honeypot.automatic-demo.com/__hp/leads/${lead!.lead.id}/dismiss`, { method: "POST", headers: { authorization: "Bearer test-admin-token" } }),
			flakyEnv,
			createExecutionContext(),
			cfg,
		);
		expect(res.status).toBe(200);
		expect(flaky.state.thrown).toBe(2);
		expect((await getLead(env.DB, lead!.lead.id))?.status).toBe("dismissed");
	});
});
