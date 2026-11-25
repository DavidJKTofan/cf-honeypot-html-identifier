import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { recordLead } from "../src/approvals/leads";
import { loadConfig } from "../src/core/config";
import { claimLead, createCase, dismissPendingLead, getFlag, getLead, recordPendingFlag, updateCase, upsertActiveFlag, type LeadRow } from "../src/storage/d1";

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
