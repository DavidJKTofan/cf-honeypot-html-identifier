import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import {
	applyFlag,
	recordApprovedFlag,
	reconcileWafList,
	removeBlocksFromWafDetailed,
	syncBlocksToWaf,
	WafSyncError,
} from "../src/approvals/enforce";
import { loadConfig } from "../src/core/config";
import { nowSec } from "../src/core/util";
import { canonicalIp } from "../src/identity/token";
import { CfApi, CfApiError } from "../src/integrations/cloudflare/api";
import { deleteExpiredFlags, getFlag, indicatorFor, listExpiredFlags, parseIndicator, type BlockFlag } from "../src/storage/d1";

const LIST = "list0000000000000000000000000001";
const cfg = { ...loadConfig(env), wafListId: LIST };

interface Call {
	method: string;
	path: string;
	query: URLSearchParams;
	body: unknown;
}

type Handler = (c: Call, n: number) => Response | Promise<Response>;

const ok = (result: unknown, extra: Record<string, unknown> = {}) => Response.json({ success: true, errors: [], messages: [], result, ...extra });
const err = (status: number, headers: Record<string, string> = {}) =>
	Response.json({ success: false, errors: [{ code: 10000, message: `status ${status}` }], messages: [], result: null }, { status, headers });

/** A CfApi whose fetch never leaves the test: every call is recorded and answered by `handler`. */
function fakeApi(handler: Handler) {
	const calls: Call[] = [];
	const sleeps: number[] = [];
	const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(input instanceof Request ? input.url : String(input));
		const call: Call = {
			method: init?.method ?? "GET",
			path: url.pathname.replace(/^\/client\/v4\/accounts\/acct/, ""),
			query: url.searchParams,
			body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
		};
		calls.push(call);
		return handler(call, calls.length);
	}) as typeof fetch;
	const api = new CfApi("token", "acct", { fetcher, sleep: async (ms) => void sleeps.push(ms) });
	return { api, calls, sleeps };
}

const count = (calls: Call[], method: string, path: string) => calls.filter((c) => c.method === method && c.path === path).length;
const block = (ip: string): BlockFlag => ({ indicator: `ip:${ip}`, kind: "ip", action: "block", reason: "test", source: "manual", source_ref: null });

async function insertFlag(ip: string, f: { action: "decoy" | "block"; status: "pending" | "active"; expiresAt: number }): Promise<void> {
	const now = nowSec();
	await env.DB.prepare(
		`INSERT INTO flags (indicator, kind, action, status, reason, source, source_ref, created_at, updated_at, expires_at, hits)
		 VALUES (?, 'ip', ?, ?, 'test', 'manual', NULL, ?, ?, ?, 1)`,
	)
		.bind(indicatorFor("ip", ip), f.action, f.status, now, now, f.expiresAt)
		.run();
}

beforeEach(async () => {
	await env.DB.prepare("DELETE FROM flags").run();
});

describe("canonicalIp", () => {
	it("normalises single addresses and rejects ranges and garbage", () => {
		expect(canonicalIp("203.0.113.7")).toBe("203.0.113.7");
		expect(canonicalIp(" 203.0.113.7 ")).toBe("203.0.113.7");
		expect(canonicalIp("::FFFF:203.0.113.7")).toBe("203.0.113.7");
		expect(canonicalIp("2001:DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
		expect(canonicalIp("2001:0db8:0000::0001")).toBe("2001:db8::1");
		expect(canonicalIp("2001:db8::0:1")).toBe("2001:db8::1");
		expect(canonicalIp("104.0.0.0/8")).toBeNull();
		expect(canonicalIp("2001:db8::/32")).toBeNull();
		expect(canonicalIp("1.2.3.256")).toBeNull();
		expect(canonicalIp("not-an-ip")).toBeNull();
		expect(canonicalIp("")).toBeNull();
	});
});

describe("Cloudflare API retries", () => {
	it("retries a 429 after retry-after, then succeeds", async () => {
		const { api, calls, sleeps } = fakeApi((_c, n) => (n === 1 ? err(429, { "retry-after": "1" }) : ok({ operation_id: "op1" })));
		await expect(api.addListItems(LIST, [{ ip: "203.0.113.9", comment: "cf-honeypot: t" }])).resolves.toBe("op1");
		expect(count(calls, "POST", `/rules/lists/${LIST}/items`)).toBe(2);
		expect(sleeps).toEqual([1000]);
	});

	it("does not wait for a retry-after longer than the backoff cap", async () => {
		const { api, calls } = fakeApi(() => err(429, { "retry-after": "120" }));
		await expect(api.addListItems(LIST, [{ ip: "203.0.113.9", comment: "x" }])).rejects.toBeInstanceOf(CfApiError);
		expect(calls).toHaveLength(1);
	});

	it("never retries an abuse report submission on a 5xx", async () => {
		const { api, calls } = fakeApi(() => err(503));
		await expect(api.submitAbuseReport("abuse_dmca", { act: "abuse_dmca" })).rejects.toBeInstanceOf(CfApiError);
		expect(calls).toHaveLength(1);
	});
});

describe("syncBlocksToWaf", () => {
	it("reports a failed bulk operation as an error (and throws for Workflow steps)", async () => {
		const handler: Handler = (c) =>
			c.method === "POST"
				? ok({ operation_id: "op2" })
				: ok({ id: "op2", status: "failed", error: "This list is at the maximum number of items", completed: "2026-11-24T00:00:00Z" });
		await expect(syncBlocksToWaf(env, cfg, [block("203.0.113.10")], { api: fakeApi(handler).api })).resolves.toBe("error");
		await expect(syncBlocksToWaf(env, cfg, [block("203.0.113.10")], { api: fakeApi(handler).api, throwOnError: true })).rejects.toBeInstanceOf(WafSyncError);
	});

	it("polls a pending operation until it completes", async () => {
		const { api, sleeps } = fakeApi((c, n) =>
			c.method === "POST" ? ok({ operation_id: "op3" }) : ok({ id: "op3", status: n < 4 ? "pending" : "completed", completed: "2026-11-24T00:00:00Z" }),
		);
		await expect(syncBlocksToWaf(env, cfg, [block("203.0.113.11")], { api })).resolves.toBe("added");
		expect(sleeps.length).toBe(2);
	});

	it("writes every block of a decision in ONE bulk operation, without Cloudflare IPs", async () => {
		const rows = [];
		for (const ip of ["198.51.100.21", "198.51.100.22", "2001:DB8::0:23"]) {
			rows.push(
				(await recordApprovedFlag(env, { kind: "ip", value: ip, action: "block", reason: "case t", source: "case", sourceRef: "case-t", ttlDays: 7 })).row,
			);
		}
		const { api, calls } = fakeApi((c) => (c.method === "POST" ? ok({ operation_id: "op4" }) : ok({ id: "op4", status: "completed", completed: "x" })));
		await expect(syncBlocksToWaf(env, cfg, [...rows, block("104.16.0.1")], { api })).resolves.toBe("added");
		const posts = calls.filter((c) => c.method === "POST");
		expect(posts).toHaveLength(1);
		expect((posts[0]?.body as { ip: string }[]).map((i) => i.ip)).toEqual(["198.51.100.21", "198.51.100.22", "2001:db8::23"]);
	});
});

describe("expired block flags", () => {
	it("keeps rows whose WAF removal failed and purges the others", async () => {
		const past = nowSec() - 60;
		await insertFlag("198.51.100.1", { action: "block", status: "active", expiresAt: past }); // lookup fails
		await insertFlag("198.51.100.2", { action: "block", status: "active", expiresAt: past }); // removed
		await insertFlag("198.51.100.3", { action: "decoy", status: "pending", expiresAt: past }); // no WAF item
		await insertFlag("198.51.100.4", { action: "block", status: "active", expiresAt: nowSec() + 3600 }); // not expired

		const { api, calls } = fakeApi((c) => {
			if (c.method === "GET" && c.query.get("search") === "198.51.100.1") return err(500);
			if (c.method === "GET" && c.query.get("search") === "198.51.100.2") return ok([{ id: "item2", ip: "198.51.100.2", comment: "cf-honeypot: t" }]);
			if (c.method === "DELETE") return ok({ operation_id: "op5" });
			return ok({ id: "op5", status: "completed", completed: "x" });
		});

		// Same sequence as MaintenanceWorkflow: find (read-only) → remove list items → delete rows except failures.
		const now = nowSec();
		const expired = await listExpiredFlags(env.DB, now);
		const blockIps = expired
			.filter((r) => r.action === "block" && r.status === "active")
			.map((r) => parseIndicator(r.indicator)?.value ?? "");
		const removal = await removeBlocksFromWafDetailed(env, cfg, blockIps, { api });
		expect(removal.failed).toEqual(["198.51.100.1"]);
		expect(removal.removed).toEqual(["198.51.100.2"]);
		expect((calls.find((c) => c.method === "DELETE")?.body as { items: { id: string }[] }).items).toEqual([{ id: "item2" }]);

		const keep = new Set(removal.failed.map((ip) => indicatorFor("ip", ip)));
		await deleteExpiredFlags(
			env.DB,
			expired.map((r) => r.indicator).filter((i) => !keep.has(i)),
			now,
		);
		expect(await getFlag(env.DB, "ip:198.51.100.1")).not.toBeNull();
		expect(await getFlag(env.DB, "ip:198.51.100.2")).toBeNull();
		expect(await getFlag(env.DB, "ip:198.51.100.3")).toBeNull();
		expect(await getFlag(env.DB, "ip:198.51.100.4")).not.toBeNull();
	});
});

describe("reconcileWafList", () => {
	it("removes only cf-honeypot items without an active block flag and re-adds missing blocks", async () => {
		const future = nowSec() + 3600;
		await insertFlag("192.0.2.1", { action: "block", status: "active", expiresAt: future }); // listed, keep
		await insertFlag("192.0.2.4", { action: "block", status: "active", expiresAt: future }); // missing, re-add
		await insertFlag("192.0.2.5", { action: "decoy", status: "active", expiresAt: future }); // decoy: never listed

		const { api, calls } = fakeApi((c) => {
			if (c.method === "GET" && c.path.endsWith("/items")) {
				return c.query.get("cursor") === "page2"
					? ok([{ id: "i3", ip: "192.0.2.3", comment: "added by a human" }])
					: ok(
							[
								{ id: "i1", ip: "192.0.2.1", comment: "cf-honeypot: case a" },
								{ id: "i2", ip: "192.0.2.2", comment: "cf-honeypot: expired" },
							],
							{ result_info: { cursors: { after: "page2" } } },
						);
			}
			if (c.method === "DELETE") return ok({ operation_id: "op-del" });
			if (c.method === "POST") return ok({ operation_id: "op-add" });
			return ok({ id: "op", status: "completed", completed: "x" });
		});

		const r = await reconcileWafList(env, cfg, { api });
		expect(r.status).toBe("ok");
		expect(r.listed).toBe(3);
		expect(r.removed).toEqual(["192.0.2.2"]);
		expect(r.added).toEqual(["192.0.2.4"]);
		expect((calls.find((c) => c.method === "DELETE")?.body as { items: { id: string }[] }).items).toEqual([{ id: "i2" }]);
		expect((calls.find((c) => c.method === "POST")?.body as { ip: string }[]).map((i) => i.ip)).toEqual(["192.0.2.4"]);
	});

	it("is skipped without an API client", async () => {
		await expect(reconcileWafList(env, cfg, { api: null })).resolves.toMatchObject({ status: "skipped" });
	});

	it("skips orphan removal when the active-block query hits its cap (the rest may be unread)", async () => {
		const future = nowSec() + 3600;
		await insertFlag("192.0.2.1", { action: "block", status: "active", expiresAt: future }); // listed
		await insertFlag("192.0.2.4", { action: "block", status: "active", expiresAt: future }); // missing, re-add
		const { api, calls } = fakeApi((c) => {
			if (c.method === "GET" && c.path.endsWith("/items"))
				return ok([
					{ id: "i1", ip: "192.0.2.1", comment: "cf-honeypot: a" },
					{ id: "i2", ip: "192.0.2.2", comment: "cf-honeypot: maybe active beyond the cap" },
				]);
			if (c.method === "POST") return ok({ operation_id: "op-add" });
			return ok({ id: "op", status: "completed", completed: "x" });
		});
		const r = await reconcileWafList(env, cfg, { api, maxFlags: 2 });
		expect(r.removed).toEqual([]);
		expect(calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
		expect(r.added).toEqual(["192.0.2.4"]);
	});
});

describe("block to decoy (H1)", () => {
	it("removes the WAF list item when an active block becomes a decoy", async () => {
		await insertFlag("192.0.2.40", { action: "block", status: "active", expiresAt: nowSec() + 3600 });
		const { api, calls } = fakeApi((c) => {
			if (c.method === "GET" && c.query.get("search") === "192.0.2.40") return ok([{ id: "i40", ip: "192.0.2.40", comment: "cf-honeypot: t" }]);
			if (c.method === "DELETE") return ok({ operation_id: "op-d" });
			return ok({ id: "op-d", status: "completed", completed: "x" });
		});
		const decoy = { kind: "ip" as const, value: "192.0.2.40", action: "decoy" as const, reason: "manual", source: "manual" as const, sourceRef: null, ttlDays: 1 };
		const r = await applyFlag(env, cfg, decoy, { api });
		expect(r.flag).toMatchObject({ action: "decoy", status: "active" });
		expect(r.waf).toBe("removed");
		expect((calls.find((c) => c.method === "DELETE")?.body as { items: { id: string }[] }).items).toEqual([{ id: "i40" }]);

		// Decoy again (no block to undo): no list call at all.
		const none = fakeApi(() => {
			throw new Error("no Lists API call expected");
		});
		await expect(applyFlag(env, cfg, decoy, { api: none.api })).resolves.toMatchObject({ waf: "not_applicable" });
		expect(none.calls).toHaveLength(0);
	});
});

describe("admin flag validation", () => {
	const admin = (path: string, init: RequestInit = {}) =>
		exports.default.fetch(`https://honeypot.automatic-demo.com/__hp${path}`, {
			...init,
			headers: { authorization: "Bearer test-admin-token", "content-type": "application/json" },
		});

	it("rejects CIDR ranges, garbage IPs and malformed JA4 values", async () => {
		for (const body of [{ ip: "104.0.0.0/8", action: "block" }, { ip: "nonsense" }, { ja4: "bad ja4!" }]) {
			const res = await admin("/flags", { method: "POST", body: JSON.stringify(body) });
			expect(res.status, JSON.stringify(body)).toBe(400);
		}
		expect(await getFlag(env.DB, "ip:104.0.0.0/8")).toBeNull();
	});

	it("stores and deletes IPv6 flags in canonical form", async () => {
		const res = await admin("/flags", { method: "POST", body: JSON.stringify({ ip: "2001:DB8:0::7", action: "decoy" }) });
		expect(res.status).toBe(201);
		expect(((await res.json()) as { flag: { indicator: string } }).flag.indicator).toBe("ip:2001:db8::7");
		const del = await admin(`/flags/${encodeURIComponent("ip:2001:0DB8::0007")}`, { method: "DELETE" });
		expect(del.status).toBe(200);
		expect(await getFlag(env.DB, "ip:2001:db8::7")).toBeNull();
	});
});
