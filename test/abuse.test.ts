/**
 * Abuse bounds on the public endpoints: beacon lead spam (per host, per token,
 * global, Origin check), the trap's global pending-flag budget, beacon privacy
 * and capture truncation. Rate limiters are replaced by deterministic fakes
 * (Miniflare's local limiter uses wall-clock windows, which makes counts flaky).
 */
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { fetchPage } from "../src/admin/decode";
import { loadConfig } from "../src/core/config";
import { sha256Hex } from "../src/core/util";
import { handleBeacon } from "../src/honeypot/beacon";
import { handleTrap } from "../src/honeypot/trap";
import { collectSignals } from "../src/identity/fingerprint";
import { importTokenKey, sealToken } from "../src/identity/token";

const BASE = "https://honeypot.automatic-demo.com";

/** A limiter that allows `max` calls per key. */
function fakeLimiter(max: number) {
	const counts = new Map<string, number>();
	return {
		calls: counts,
		limit: async ({ key }: { key: string }) => {
			const n = (counts.get(key) ?? 0) + 1;
			counts.set(key, n);
			return { success: n <= max };
		},
	};
}

type Point = { indexes?: unknown[]; blobs?: unknown[]; doubles?: unknown[] };

function harness(limits: { beacon?: number; lead?: number; trap?: number; trapGlobal?: number } = {}) {
	const points: Point[] = [];
	const fakeEnv = {
		...env,
		EVENTS: { writeDataPoint: (p: Point) => points.push(p) },
		BEACON_LIMITER: fakeLimiter(limits.beacon ?? 1000),
		LEAD_LIMITER: fakeLimiter(limits.lead ?? 1000),
		TRAP_LIMITER: fakeLimiter(limits.trap ?? 1000),
		TRAP_GLOBAL_LIMITER: fakeLimiter(limits.trapGlobal ?? 1000),
	} as unknown as Env;
	return { fakeEnv, points, cfg: loadConfig(fakeEnv) };
}

async function tokenFor(rayId: string): Promise<string> {
	return sealToken(
		{ issuedAt: 1_700_000_000, ip: "203.0.113.9", asn: 64496, country: "DE", colo: "FRA", botScore: null, verifiedBot: false, jsDetectionPassed: false, botManagement: false, rayId },
		await importTokenKey(env.TOKEN_KEY),
	);
}

async function beacon(h: ReturnType<typeof harness>, body: unknown, headers: Record<string, string> = {}, cf?: Record<string, unknown>): Promise<void> {
	const ctx = createExecutionContext();
	const req = new Request(`${BASE}/api/rum`, {
		method: "POST",
		body: JSON.stringify(body),
		headers: { "content-type": "text/plain", "cf-connecting-ip": "192.0.2.77", "user-agent": "VisitorBrowser/1.0", ...headers },
		...(cf ? { cf } : {}),
	});
	const res = await handleBeacon(req, h.fakeEnv, ctx, h.cfg);
	expect(res.status).toBe(204);
	await waitOnExecutionContext(ctx);
}

async function leadCount(where: string, arg: string): Promise<number> {
	const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM leads WHERE ${where}`).bind(arg).first<{ n: number }>();
	return row?.n ?? 0;
}

describe("beacon lead bounds", () => {
	it("new rate limit bindings exist", () => {
		expect(typeof env.LEAD_LIMITER.limit).toBe("function");
		expect(typeof env.TRAP_GLOBAL_LIMITER.limit).toBe("function");
	});

	it("one token cannot fan out to many invented hosts (per-token key)", async () => {
		const h = harness({ beacon: 10 });
		const ray = "aaaaaaaaaaaa0001";
		const t = await tokenFor(ray);
		for (let i = 0; i < 15; i++) await beacon(h, { t, u: `https://rot${i}.tokenspam.example/p` });
		expect(await leadCount("token_ray = ?", ray)).toBe(10);
	});

	it("caps lead upserts globally, whatever the host or token", async () => {
		const h = harness({ lead: 3 });
		for (let i = 0; i < 5; i++) {
			const t = await tokenFor(`bbbbbbbbbbbb000${i}`);
			await beacon(h, { t, u: `https://g${i}.globalspam.example/` });
		}
		expect(await leadCount("host LIKE ?", "%.globalspam.example")).toBe(3);
	});

	it("rejects a real Origin that differs from the reported page, accepts a missing or null Origin", async () => {
		const h = harness();
		const t = await tokenFor("cccccccccccc0001");
		await beacon(h, { t, u: "https://mismatch.origin.example/" }, { origin: "https://attacker.example" });
		expect(await leadCount("host = ?", "mismatch.origin.example")).toBe(0);
		expect(h.points.at(-1)?.blobs?.[0]).toBe("beacon_invalid");

		await beacon(h, { t, u: "https://nullorigin.origin.example/" }, { origin: "null" });
		await beacon(h, { t, u: "https://same.origin.example/x" }, { origin: "https://same.origin.example" });
		expect(await leadCount("host = ?", "nullorigin.origin.example")).toBe(1);
		expect(await leadCount("host = ?", "same.origin.example")).toBe(1);
	});

	it("stores nothing that identifies the clone's visitor in Analytics Engine", async () => {
		const h = harness();
		const t = await tokenFor("dddddddddddd0001");
		await beacon(
			h,
			{ t, u: "https://privacy.example/" },
			{ "accept-language": "de-DE", "cf-ray": "0123456789abcdef-FRA" },
			{ city: "Berlin", asOrganization: "Visitor ISP", asn: 64500, clientTcpRtt: 12, country: "DE", colo: "FRA" },
		);
		const p = h.points.at(-1);
		expect(p?.blobs?.[0]).toBe("beacon");
		const [, , , ip, ua, ja4, ja3, asOrg, country, , city, , , , lang, detection, , rayId] = p?.blobs ?? [];
		expect({ ip, ua, ja4, ja3, asOrg, city, lang, detection, rayId }).toEqual({ ip: "", ua: "", ja4: "", ja3: "", asOrg: "", city: "", lang: "", detection: "", rayId: "" });
		expect(country).toBe("DE"); // coarse location is kept
		expect(p?.doubles?.[1]).toBe(0); // ASN
		expect(p?.doubles?.[3]).toBe(-1); // client TCP RTT
		expect(p?.blobs?.[19]).toBe("dddddddddddd0001"); // note = token Ray ID (the scraper's request, not the visitor's)
	});
});

describe("trap global bound", () => {
	it("skips the D1 write when the global budget is exhausted, but still serves the decoy", async () => {
		const h = harness({ trapGlobal: 1 });
		for (const ip of ["198.18.0.1", "198.18.0.2"]) {
			const ctx = createExecutionContext();
			const s = collectSignals(new Request(`${BASE}/catalog/full-export`, { headers: { "cf-connecting-ip": ip } }));
			const res = await handleTrap(h.fakeEnv, ctx, h.cfg, s, BASE);
			expect(await res.text()).toContain("Catalog export");
			await waitOnExecutionContext(ctx);
		}
		const first = await env.DB.prepare("SELECT status FROM flags WHERE indicator = ?").bind("ip:198.18.0.1").first<{ status: string }>();
		const second = await env.DB.prepare("SELECT 1 FROM flags WHERE indicator = ?").bind("ip:198.18.0.2").first();
		expect(first?.status).toBe("pending");
		expect(second).toBeNull();
	});
});

describe("evidence capture size cap", () => {
	function streamed(chunks: number[], onCancel: () => void): Response {
		let i = 0;
		const body = new ReadableStream<Uint8Array>({
			pull(controller) {
				const size = chunks[i];
				if (size === undefined) return controller.close();
				controller.enqueue(new Uint8Array(size).fill(65 + i));
				i++;
			},
			cancel: onCancel,
		});
		return new Response(body, { headers: { "content-type": "text/html" } });
	}

	it("keeps the first maxBytes of an oversized page instead of failing, and hashes what it kept", async () => {
		let cancelled = false;
		const page = await fetchPage("https://padded.example/", 2500, async () => streamed([1000, 1000, 1000, 1000], () => (cancelled = true)));
		expect(page.truncated).toBe(true);
		expect(page.bytes.byteLength).toBe(2500);
		expect(page.sha256).toBe(await sha256Hex(page.bytes));
		expect(page.finalUrl).toBe("https://padded.example/");
		expect(cancelled).toBe(true);
	});

	it("is not truncated when the page fits exactly", async () => {
		const page = await fetchPage("https://exact.example/", 2000, async () => streamed([1000, 1000], () => undefined));
		expect(page.truncated).toBe(false);
		expect(page.bytes.byteLength).toBe(2000);
	});
});
