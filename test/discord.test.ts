import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { loadConfig, type Config } from "../src/core/config";
import { updateOrPostLead, type LeadNotice, type Notifier } from "../src/notify";
import type { DiscordApi } from "../src/notify/discord/api";
import { handleDiscordInteraction } from "../src/notify/discord/interactions";
import { caseMessage, decodeAction, encodeAction, flagsMessage, leadMessage, resolvedPayload } from "../src/notify/discord/messages";
import { DiscordBotNotifier, DiscordWebhookNotifier } from "../src/notify/discord/notifier";
import { verifyDiscordSignature } from "../src/notify/discord/verify";
import { flakyD1 } from "./flaky-d1";

const APPROVER = "111111111111111111";
const STRANGER = "222222222222222222";
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");

let keys: CryptoKeyPair;
let publicKeyHex: string;
let cfg: Config;

beforeAll(async () => {
	keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	publicKeyHex = hex((await crypto.subtle.exportKey("raw", keys.publicKey)) as ArrayBuffer);
	cfg = loadConfig({
		...env,
		DISCORD_PUBLIC_KEY: publicKeyHex,
		DISCORD_APPROVER_IDS: APPROVER,
		DISCORD_API_BASE: "http://127.0.0.1:9", // never reach Discord from tests
	});
});

async function signed(body: unknown, opts: { tamper?: boolean; timestamp?: number } = {}): Promise<Request> {
	const raw = JSON.stringify(body);
	const ts = String(opts.timestamp ?? Math.floor(Date.now() / 1000));
	const sig = hex(await crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(ts + raw)));
	return new Request("https://honeypot.automatic-demo.com/integrations/discord/interactions", {
		method: "POST",
		headers: { "x-signature-ed25519": sig, "x-signature-timestamp": ts, "content-type": "application/json" },
		body: opts.tamper ? raw.replace("1", "2") : raw,
	});
}

const click = (customId: string, userId: string) => ({
	type: 3,
	token: "interaction-token",
	application_id: "333333333333333333",
	data: { custom_id: customId, component_type: 2 },
	member: { user: { id: userId }, roles: [] },
	message: { id: "444", embeds: [{ title: "x", fields: [] }], components: [] },
});

async function call(req: Request, callEnv: Env = env) {
	const ctx = createExecutionContext();
	const res = await handleDiscordInteraction(req, callEnv, ctx, cfg);
	await waitOnExecutionContext(ctx);
	return res;
}

describe("Discord signature verification", () => {
	it("accepts valid and rejects tampered, stale or malformed signatures", async () => {
		const ts = String(Math.floor(Date.now() / 1000));
		const body = '{"type":1}';
		const sig = hex(await crypto.subtle.sign("Ed25519", keys.privateKey, new TextEncoder().encode(ts + body)));
		expect(await verifyDiscordSignature(publicKeyHex, sig, ts, body)).toBe(true);
		expect(await verifyDiscordSignature(publicKeyHex, sig, ts, '{"type":2}')).toBe(false);
		expect(await verifyDiscordSignature(publicKeyHex, sig, String(Number(ts) - 3600), body)).toBe(false);
		expect(await verifyDiscordSignature(publicKeyHex, "zz", ts, body)).toBe(false);
	});
});

describe("Discord interactions endpoint", () => {
	it("answers PING with PONG and rejects bad signatures with 401", async () => {
		expect(await (await call(await signed({ type: 1 }))).json()).toEqual({ type: 1 });
		expect((await call(await signed({ type: 1 }, { tamper: true }))).status).toBe(401);
	});

	it("reports access for the setup check button", async () => {
		const res = (await (await call(await signed(click(encodeAction("test", "ping", "0"), STRANGER)))).json()) as {
			type: number;
			data: { content: string; flags: number };
		};
		expect(res.type).toBe(4);
		expect(res.data.flags).toBe(64);
		expect(res.data.content).toContain("not");
	});

	it("refuses clicks from non-approvers", async () => {
		const res = (await (await call(await signed(click(encodeAction("lead", "dismiss", 1), STRANGER)))).json()) as { data: { content: string } };
		expect(res.data.content).toMatch(/not allowed/i);
	});

	it("lets an approver dismiss a pending lead (deferred update, then DB change)", async () => {
		const lead = await env.DB.prepare(
			"INSERT INTO leads (host, sample_url, source, status, first_seen, last_seen) VALUES ('discord-test.example', NULL, 'manual', 'pending', 1, 1) RETURNING id",
		).first<{ id: number }>();
		const res = await call(await signed(click(encodeAction("lead", "dismiss", lead!.id), APPROVER)));
		expect(await res.json()).toEqual({ type: 6 });
		const row = await env.DB.prepare("SELECT status FROM leads WHERE id = ?").bind(lead!.id).first<{ status: string }>();
		expect(row?.status).toBe("dismissed");
	});

	it("retries a click's D1 write after a transient error (L3)", async () => {
		const lead = await env.DB.prepare(
			"INSERT INTO leads (host, sample_url, source, status, first_seen, last_seen) VALUES ('discord-retry.example', NULL, 'manual', 'pending', 1, 1) RETURNING id",
		).first<{ id: number }>();
		const flaky = flakyD1(env.DB, 2);
		const res = await call(await signed(click(encodeAction("lead", "dismiss", lead!.id), APPROVER)), { ...env, DB: flaky.db } as Env);
		expect(await res.json()).toEqual({ type: 6 });
		expect(flaky.state.thrown).toBe(2);
		const row = await env.DB.prepare("SELECT status FROM leads WHERE id = ?").bind(lead!.id).first<{ status: string }>();
		expect(row?.status).toBe("dismissed");
	});
});

describe("Discord message helpers", () => {
	it("round-trips custom ids, including IPv6 indicators", () => {
		const id = encodeAction("flag", "decoy", "ip:2001:db8::1");
		expect(decodeAction(id)).toEqual({ kind: "flag", action: "decoy", arg: "ip:2001:db8::1" });
		expect(decodeAction("other|thing")).toBeNull();
	});

	it("removes only the clicked digest row and keeps the others actionable", () => {
		const message = {
			embeds: [{ title: "flags", fields: [] }],
			components: [
				{ type: 1, components: [{ custom_id: "hp|flag|decoy|ip:a" }, { custom_id: "hp|flag|reject|ip:a" }] },
				{ type: 1, components: [{ custom_id: "hp|flag|decoy|ip:b" }] },
			],
		};
		const out = resolvedPayload(message, "Done", { type: "row", customId: "hp|flag|reject|ip:a" }) as { components: unknown[] };
		expect(out.components).toHaveLength(1);
		expect((resolvedPayload(message, "Done") as { components: unknown[] }).components).toHaveLength(0);
	});
});

describe("lead corroborated by a beacon", () => {
	const notice: LeadNotice = {
		id: 7,
		host: "look-alike.example",
		source: "brand_protection",
		sampleUrl: "https://look-alike.example/",
		tokenRay: "0123456789abcdef",
		firstSeen: 1,
		hits: 2,
		corroborated: true,
	};

	it("says it is corroborated, shows the token Ray ID once, and keeps the buttons", () => {
		const p = leadMessage(notice, true);
		const embed = JSON.stringify(p.embeds);
		expect(embed).toContain("Corroborated clone lead");
		expect(embed).toContain("Corroborated by beacon");
		expect(embed).toContain("Still unconfirmed");
		expect(embed.match(/0123456789abcdef/g)).toHaveLength(1);
		expect(JSON.stringify(p.components)).toContain("hp|lead|approve|7");
		expect(p.allowed_mentions).toEqual({ parse: [] });
		// Untrusted values render as inline code.
		expect(embed).toContain("(Ray `0123456789abcdef`)");
	});

	it("the bot edits the original message in place; the webhook can't, so the caller posts", async () => {
		const editMessage = vi.fn(async () => ({ id: "2", channel_id: "1" }));
		const createMessage = vi.fn(async () => ({ id: "3", channel_id: "1" }));
		const bot = new DiscordBotNotifier({ editMessage, createMessage } as unknown as DiscordApi, "1");
		expect(await bot.updateLead("discord:1:2", notice)).toBe(true);
		expect(editMessage).toHaveBeenCalledWith("1", "2", leadMessage(notice, true));
		expect(await bot.updateLead("discord-webhook:1:2", notice)).toBe(false);
		expect(createMessage).not.toHaveBeenCalled();
		expect(await new DiscordWebhookNotifier("http://127.0.0.1:9/webhook").updateLead()).toBe(false);
	});

	it("updateOrPostLead edits when it can and posts one new message otherwise", async () => {
		const fake = (update: () => Promise<boolean>) => {
			const n = { updateLead: vi.fn(update), notifyLead: vi.fn(async () => "discord:1:99") };
			return { n, notifier: n as unknown as Notifier };
		};
		const edits = fake(async () => true);
		expect(await updateOrPostLead(edits.notifier, "discord:1:2", notice)).toBe("discord:1:2");
		expect(edits.n.notifyLead).not.toHaveBeenCalled();

		const noRef = fake(async () => true);
		expect(await updateOrPostLead(noRef.notifier, null, notice)).toBe("discord:1:99");
		expect(noRef.n.updateLead).not.toHaveBeenCalled();

		for (const update of [async () => false, async () => Promise.reject(new Error("Unknown Message"))]) {
			const f = fake(update);
			expect(await updateOrPostLead(f.notifier, "discord:1:2", notice)).toBe("discord:1:99");
			expect(f.n.notifyLead).toHaveBeenCalledTimes(1);
		}
	});
});

describe("message wording", () => {
	const caseBase = {
		caseId: "case-1",
		url: "https://clone.example/",
		host: "clone.example",
		sha256: "ab".repeat(32),
		tokenCount: 1,
		hostedOnCloudflare: true,
		scanReportUrl: null,
		abuseSubmitAvailable: false,
		abuseAct: "abuse_dmca",
	};
	const line = { ip: "203.0.113.7", asn: 64496, org: null, country: "DE", botScore: 1, fetchedAt: "2026-11-24T22:35:43.000Z", rayId: "0123456789abcdef", viaCloudflare: false };
	const labels = (p: { components: unknown[] }) => JSON.stringify(p.components);

	it("case buttons say they act on the case, digest buttons name the IP", () => {
		expect(labels(caseMessage({ ...caseBase, attribution: [line] }, true))).toContain("Decoy case IPs");
		expect(labels(flagsMessage([{ indicator: "ip:203.0.113.7", reason: "trap hit", hits: 1, createdAt: 1 }], 1, true))).toContain("Block 203.0.113.7");
	});

	it("marks beacon-only evidence as unconfirmed, and verified bots / live proxies in attribution", () => {
		const p = caseMessage({ ...caseBase, beaconOnly: true, attribution: [{ ...line, fromBeacon: true }, { ...line, ip: "66.249.66.1", verifiedBot: true }, { ...line, liveMirror: true }] }, true);
		const embed = JSON.stringify(p.embeds);
		expect(embed).toContain("unconfirmed copy");
		expect(embed).toContain("reported by beacon (unconfirmed)");
		expect(embed).toContain("verified bot: never flagged");
		expect(embed).toContain("live reverse proxy");
		// No draft exists for beacon-only evidence, so the hosting line must not claim one.
		expect(embed).toContain("No abuse report draft");
		expect(embed).not.toContain("draft is in the evidence bundle");
	});

	it("titles a re-opened lead as a re-scrape", () => {
		const p = leadMessage({ id: 1, host: "clone.example", source: "beacon", sampleUrl: null, tokenRay: null, firstSeen: 1, hits: 3, reopened: true }, true);
		expect(JSON.stringify(p.embeds)).toContain("Re-scraped clone: clone.example");
	});

	it("explains the lead source, and never calls a Brand Protection match a copy", () => {
		const lead = { id: 1, host: "look-alike.example", sampleUrl: "https://look-alike.example/", tokenRay: null, firstSeen: 1, hits: 1 };
		const brand = JSON.stringify(leadMessage({ ...lead, source: "brand_protection" }, true).embeds);
		expect(brand).toContain("not proof of a copy");
		expect(brand).not.toContain("appears to run a copy");
		expect(JSON.stringify(leadMessage({ ...lead, source: "beacon" }, true).embeds)).toContain("reported a valid token");
		expect(JSON.stringify(leadMessage({ ...lead, source: "referer" }, true).embeds)).toContain("foreign Referer");
		expect(JSON.stringify(leadMessage({ ...lead, source: "manual" }, true).embeds)).toContain("appears to run a copy");
	});
});
