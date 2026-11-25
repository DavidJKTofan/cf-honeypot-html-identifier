import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { recordLead } from "../src/approvals/leads";
import { loadConfig } from "../src/core/config";
import {
	claimLead,
	createCase,
	dismissPendingLead,
	getFlag,
	getLead,
	recordPendingFlag,
	updateCase,
	upsertActiveFlag,
	upsertLead,
	type LeadRow,
	type LeadSource,
} from "../src/storage/d1";

const cfg = loadConfig(env);

/** A beacon report as the handler passes it (token already validated). */
const beacon = (host: string, tokenIp: string, tokenRay: string) => ({
	host,
	sampleUrl: `https://${host}/`,
	source: "beacon" as const,
	tokenRay,
	token: `tok-${tokenRay}`,
	tokenIp,
});

/** A lead from a weaker discovery channel, as the maintenance Workflow records it (no token). */
const weak = (host: string, source: LeadSource) => ({ host, sampleUrl: `https://${host}/`, source, tokenRay: null });

const CHANNEL = "800000000000000001";
const MESSAGE = "900000000000000001";

/** An env whose Discord bot notifier works, with every Discord API call captured (nothing leaves the test). */
function discordEnv(db: D1Database = env.DB) {
	const calls: { method: string; path: string; body: string }[] = [];
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		calls.push({ method: init?.method ?? "GET", path: new URL(String(input)).pathname, body: String(init?.body ?? "") });
		return Response.json({ id: MESSAGE, channel_id: CHANNEL });
	});
	const e = {
		...env,
		DB: db,
		DISCORD_BOT_TOKEN: "test-bot-token",
		DISCORD_CHANNEL_ID: CHANNEL,
		DISCORD_API_BASE: "http://127.0.0.1:9",
		NOTIFY_LIMITER: { limit: async () => ({ success: true }) },
	} as unknown as Env;
	return { calls, env: e, cfg: loadConfig(e) };
}

afterEach(() => {
	vi.restoreAllMocks();
});

async function approvedLead(host: string, ip = "203.0.113.10"): Promise<LeadRow> {
	const r = await recordLead(env, cfg, beacon(host, ip, "aaaaaaaaaaaaaaaa"));
	if (!r) throw new Error("no lead");
	expect(await claimLead(env.DB, r.lead.id)).toBe(true);
	return r.lead;
}

describe("beacon evidence on leads", () => {
	it("stores the full beacon token and the scraper IP it names", async () => {
		const r = await recordLead(env, cfg, beacon("evidence.example", "203.0.113.5", "bbbbbbbbbbbbbbbb"));
		expect(r?.lead).toMatchObject({ status: "pending", token: "tok-bbbbbbbbbbbbbbbb", token_ip: "203.0.113.5", token_ray: "bbbbbbbbbbbbbbbb" });
	});

	it("keeps the first token while the lead is pending (dedupe, no fan-out)", async () => {
		await recordLead(env, cfg, beacon("dedupe.example", "203.0.113.5", "cccccccccccccccc"));
		const r = await recordLead(env, cfg, beacon("dedupe.example", "198.51.100.5", "dddddddddddddddd"));
		expect(r).toMatchObject({ isNew: false, reopened: false });
		expect(r?.lead).toMatchObject({ status: "pending", hits: 2, token_ip: "203.0.113.5" });
	});
});

describe("re-scrape re-opens an investigated host", () => {
	it("same scraper IP: only a hit, the lead stays approved", async () => {
		const lead = await approvedLead("same-ip.example");
		const r = await recordLead(env, cfg, beacon("same-ip.example", "203.0.113.10", "eeeeeeeeeeeeeeee"));
		expect(r?.reopened).toBe(false);
		expect(await getLead(env.DB, lead.id)).toMatchObject({ status: "approved", hits: 2 });
	});

	it("new scraper IP: back to pending with the new token, once per cooldown", async () => {
		const lead = await approvedLead("rescraped.example");
		const r = await recordLead(env, cfg, beacon("rescraped.example", "198.51.100.77", "ffffffffffffffff"));
		expect(r?.reopened).toBe(true);
		expect(r?.lead).toMatchObject({ status: "pending", case_id: null, token: "tok-ffffffffffffffff", token_ip: "198.51.100.77", token_ray: "ffffffffffffffff" });
		expect(r?.lead.reopened_at).toBeGreaterThan(0);

		// Approved again, then yet another IP within the cooldown: not re-opened (no notification storm).
		expect(await claimLead(env.DB, lead.id)).toBe(true);
		const again = await recordLead(env, cfg, beacon("rescraped.example", "192.0.2.99", "1212121212121212"));
		expect(again?.reopened).toBe(false);
		expect(await getLead(env.DB, lead.id)).toMatchObject({ status: "approved", token_ip: "198.51.100.77" });
	});

	it("never re-opens a dismissed lead", async () => {
		const r = await recordLead(env, cfg, beacon("dismissed.example", "203.0.113.10", "abababababababab"));
		expect(await dismissPendingLead(env.DB, r!.lead.id)).toBe(true);
		const next = await recordLead(env, cfg, beacon("dismissed.example", "198.51.100.1", "cdcdcdcdcdcdcdcd"));
		expect(next?.reopened).toBe(false);
		expect(next?.lead.status).toBe("dismissed");
	});

	it("never re-opens while a case for the host is still open", async () => {
		const lead = await approvedLead("open-case.example");
		await createCase(env.DB, { id: "case-open-reopen", leadId: lead.id, url: "https://open-case.example/", host: "open-case.example" });
		const r = await recordLead(env, cfg, beacon("open-case.example", "198.51.100.2", "efefefefefefefef"));
		expect(r?.reopened).toBe(false);
		await updateCase(env.DB, "case-open-reopen", { status: "closed" });
		const after = await recordLead(env, cfg, beacon("open-case.example", "198.51.100.3", "0101010101010101"));
		expect(after?.reopened).toBe(true);
	});
});

describe("a beacon corroborates a weaker lead", () => {
	it("updates the original message in place, once, and keeps the source", async () => {
		const d = discordEnv();
		const first = await recordLead(d.env, d.cfg, weak("hotlinker.example", "referer"));
		expect(first).toMatchObject({ isNew: true, corroborated: false });
		expect(d.calls.map((c) => c.method)).toEqual(["POST"]);
		expect((await getLead(env.DB, first!.lead.id))?.notify_ref).toBe(`discord:${CHANNEL}:${MESSAGE}`);

		const r = await recordLead(d.env, d.cfg, beacon("hotlinker.example", "203.0.113.20", "1a1a1a1a1a1a1a1a"));
		expect(r).toMatchObject({ isNew: false, reopened: false, corroborated: true });
		expect(r?.lead).toMatchObject({ status: "pending", source: "referer", hits: 2, token: "tok-1a1a1a1a1a1a1a1a", token_ip: "203.0.113.20", token_ray: "1a1a1a1a1a1a1a1a" });
		expect(d.calls).toHaveLength(2);
		expect(d.calls[1]).toMatchObject({ method: "PATCH", path: `/channels/${CHANNEL}/messages/${MESSAGE}` });
		expect(d.calls[1]?.body).toContain("Corroborated clone lead: hotlinker.example");
		expect(d.calls[1]?.body).toContain("1a1a1a1a1a1a1a1a");
		expect(d.calls[1]?.body).toContain(`hp|lead|approve|${first!.lead.id}`); // still actionable

		// Later beacons only add hits: the first token stays and nobody is notified again.
		const again = await recordLead(d.env, d.cfg, beacon("hotlinker.example", "198.51.100.20", "2b2b2b2b2b2b2b2b"));
		expect(again).toMatchObject({ corroborated: false, reopened: false });
		expect(again?.lead).toMatchObject({ hits: 3, token_ip: "203.0.113.20" });
		expect(d.calls).toHaveLength(2);
	});

	it("posts one new message when the lead has none to edit", async () => {
		// First sight with notifications off (or rate-limited): no notify_ref.
		const first = await recordLead(env, cfg, weak("look-alike.example", "brand_protection"));
		expect(first?.lead.notify_ref).toBeNull();
		const d = discordEnv();
		const r = await recordLead(d.env, d.cfg, beacon("look-alike.example", "203.0.113.21", "3c3c3c3c3c3c3c3c"));
		expect(r?.corroborated).toBe(true);
		expect(d.calls.map((c) => c.method)).toEqual(["POST"]);
		expect(d.calls[0]?.body).toContain("Corroborated clone lead: look-alike.example");
		expect((await getLead(env.DB, first!.lead.id))?.notify_ref).toBe(`discord:${CHANNEL}:${MESSAGE}`);
	});

	it("never escalates a beacon lead, even an older one stored without its token", async () => {
		const d = discordEnv();
		await recordLead(d.env, d.cfg, beacon("beacon-first.example", "203.0.113.22", "4d4d4d4d4d4d4d4d"));
		const next = await recordLead(d.env, d.cfg, beacon("beacon-first.example", "198.51.100.22", "5e5e5e5e5e5e5e5e"));
		expect(next?.corroborated).toBe(false);

		// A beacon lead from before 0004 has a Ray ID but no token: the token is attached, quietly.
		const legacy = await upsertLead(env.DB, { host: "legacy-beacon.example", sampleUrl: null, source: "beacon", tokenRay: "6f6f6f6f6f6f6f6f" });
		const calls = d.calls.length;
		const r = await recordLead(d.env, d.cfg, beacon("legacy-beacon.example", "203.0.113.23", "7a7a7a7a7a7a7a7a"));
		expect(r?.corroborated).toBe(false);
		expect(await getLead(env.DB, legacy!.lead.id)).toMatchObject({ status: "pending", token: "tok-7a7a7a7a7a7a7a7a", token_ip: "203.0.113.23" });
		expect(d.calls).toHaveLength(calls);
	});

	it("never escalates a dismissed lead, but keeps the token as evidence", async () => {
		const first = await recordLead(env, cfg, weak("dismissed-referer.example", "referer"));
		expect(await dismissPendingLead(env.DB, first!.lead.id)).toBe(true);
		const d = discordEnv();
		const r = await recordLead(d.env, d.cfg, beacon("dismissed-referer.example", "203.0.113.24", "8b8b8b8b8b8b8b8b"));
		expect(r?.corroborated).toBe(false);
		expect(r?.lead).toMatchObject({ status: "dismissed", token: "tok-8b8b8b8b8b8b8b8b" });
		expect(d.calls).toHaveLength(0);
	});

	it("never escalates an approved lead; its token still enables re-scrape detection", async () => {
		const first = await recordLead(env, cfg, weak("approved-referer.example", "referer"));
		expect(await claimLead(env.DB, first!.lead.id)).toBe(true);
		const d = discordEnv();
		const r = await recordLead(d.env, d.cfg, beacon("approved-referer.example", "203.0.113.25", "9c9c9c9c9c9c9c9c"));
		expect(r?.corroborated).toBe(false);
		expect(r?.lead).toMatchObject({ status: "approved", token_ip: "203.0.113.25" });
		expect(d.calls).toHaveLength(0);
		// A later token naming another scraper IP re-opens it, as for a beacon-sourced lead.
		const rescrape = await recordLead(d.env, d.cfg, beacon("approved-referer.example", "198.51.100.25", "adadadadadadadad"));
		expect(rescrape?.reopened).toBe(true);
	});

	it("concurrent beacons escalate exactly once", async () => {
		const first = await recordLead(env, cfg, weak("race.example", "referer"));
		// Hold every token claim back briefly, so all three beacons upsert before any of them claims.
		let claims = 0;
		const racingDb = {
			prepare(sql: string) {
				const stmt = env.DB.prepare(sql);
				if (!sql.includes("token IS NULL")) return stmt;
				return {
					bind: (...args: unknown[]) => ({
						first: async () => {
							claims++;
							await scheduler.wait(25);
							return stmt.bind(...args).first();
						},
					}),
				};
			},
		} as unknown as D1Database;
		const d = discordEnv(racingDb);
		const results = await Promise.all(
			["203.0.113.30", "203.0.113.31", "203.0.113.32"].map((ip, i) => recordLead(d.env, d.cfg, beacon("race.example", ip, `${i}e`.repeat(8)))),
		);
		expect(claims).toBe(3);
		const winners = results.filter((r) => r?.corroborated);
		expect(winners).toHaveLength(1);
		expect(d.calls.map((c) => c.method)).toEqual(["POST"]);
		const lead = await getLead(env.DB, first!.lead.id);
		expect(lead).toMatchObject({ status: "pending", hits: 4, token_ip: winners[0]?.lead.token_ip });
	});
});

describe("flag provenance", () => {
	it("a case decision on a trapped IP keeps the trap provenance in the reason", async () => {
		await recordPendingFlag(env.DB, { kind: "ip", value: "203.0.113.200", reason: "trap hit (bot score 1)", sourceRef: "a5fbec741c46469a", pendingTtlDays: 14 });
		const row = await upsertActiveFlag(env.DB, {
			kind: "ip",
			value: "203.0.113.200",
			action: "decoy",
			reason: "case case-x: copy found on clone.example",
			source: "case",
			sourceRef: "case-x",
			ttlDays: 7,
		});
		expect(row).toMatchObject({ status: "active", source: "case", source_ref: "case-x" });
		expect(row.reason).toBe("case case-x: copy found on clone.example (previously trap a5fbec741c46469a: trap hit (bot score 1))");
		// Re-applying the same decision does not stack another "previously".
		const same = await upsertActiveFlag(env.DB, { kind: "ip", value: "203.0.113.200", action: "block", reason: "case case-x: again", source: "case", sourceRef: "case-x", ttlDays: 7 });
		expect(same.reason).toBe("case case-x: again");
		expect((await getFlag(env.DB, "ip:203.0.113.200"))?.action).toBe("block");
	});
});
