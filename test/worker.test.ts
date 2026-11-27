import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";

const BASE = "https://honeypot.automatic-demo.com";
const ADMIN = { authorization: "Bearer test-admin-token" };

function get(path: string, ip: string, headers: Record<string, string> = {}): Promise<Response> {
	return exports.default.fetch(`${BASE}${path}`, { headers: { "cf-connecting-ip": ip, ...headers } });
}

function admin(path: string, init: RequestInit = {}): Promise<Response> {
	return exports.default.fetch(`${BASE}/__hp${path}`, {
		...init,
		headers: { ...ADMIN, "content-type": "application/json", ...(init.headers as Record<string, string> | undefined) },
	});
}

function metaToken(html: string): string {
	const m = /<meta name="csrf-token" content="([A-Za-z0-9_-]{91})">/.exec(html);
	if (!m?.[1]) throw new Error("no token in page");
	return m[1];
}

/** waitUntil() work may finish after the response; poll D1 briefly. */
async function eventually<T>(fn: () => Promise<T | null>, tries = 40): Promise<T> {
	for (let i = 0; i < tries; i++) {
		const v = await fn();
		if (v) return v;
		await scheduler.wait(25);
	}
	throw new Error("condition not met in time");
}

describe("page tokenization", () => {
	it("injects a sealed token into HTML and decodes back to the requester", async () => {
		const res = await get("/", "198.51.100.20");
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toBe("private, no-cache");
		const html = await res.text();
		expect(html).toContain("/assets/js/rum.js");
		const token = metaToken(html);

		const decoded = await admin("/decode", { method: "POST", body: JSON.stringify({ token }) });
		const body = (await decoded.json()) as { valid: number; results: { fingerprint: { ip: string } }[] };
		expect(body.valid).toBe(1);
		expect(body.results[0]?.fingerprint.ip).toBe("198.51.100.20");
	});

	it("decodes tokens out of pasted HTML", async () => {
		const html = await (await get("/article", "198.51.100.21")).text();
		const res = await admin("/decode", { method: "POST", body: JSON.stringify({ html }) });
		const body = (await res.json()) as { valid: number; markers: { beaconScript: boolean; trapLink: boolean } };
		expect(body.valid).toBe(1);
		expect(body.markers).toMatchObject({ beaconScript: true, trapLink: true });
	});

	it("passes a 206 partial HTML response through untouched (no token in a byte range)", async () => {
		const partial = "<!doctype html><html><head><title>t</title></head><bo";
		const assets = {
			fetch: async () => new Response(partial, { status: 206, headers: { "content-type": "text/html", "content-range": "bytes 0-52/400" } }),
		} as unknown as Fetcher;
		const ctx = createExecutionContext();
		const res = await worker.fetch(
			new Request(`${BASE}/`, { headers: { "cf-connecting-ip": "198.51.100.24", range: "bytes=0-52" } }) as Request<unknown, IncomingRequestCfProperties>,
			{ ...env, ASSETS: assets },
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(206);
		expect(res.headers.get("content-range")).toBe("bytes 0-52/400");
		expect(await res.text()).toBe(partial);
	});

	it("passes static assets through untouched", async () => {
		const res = await get("/styles.css", "198.51.100.22");
		expect(res.headers.get("content-type")).toContain("text/css");
		expect(await res.text()).not.toContain("csrf-token");
	});

	it("adds the trap path to robots.txt and serves the beacon script", async () => {
		expect(await (await get("/robots.txt", "198.51.100.23")).text()).toContain("Disallow: /catalog/full-export");
		const js = await get("/assets/js/rum.js", "198.51.100.23");
		expect(js.headers.get("content-type")).toContain("javascript");
	});
});

/**
 * C1 and C2, as integration tests against the real bindings: requests go through
 * `exports.default.fetch()`, the demo origin is the real Static Assets binding (which sends an
 * ETag, `public, max-age=0, must-revalidate`, answers HEAD without a body and If-None-Match with
 * a real 304), and Analytics Engine writes are counted with a spy that calls through to the real
 * binding. Every "no event" assertion has a GET in the same test as its positive control, so it
 * can't pass just because the spy sees nothing.
 */
describe("bodiless responses and origin cache headers (C1, C2)", () => {
	const page = (ip: string, init: RequestInit = {}) =>
		exports.default.fetch(`${BASE}/`, { ...init, headers: { "cf-connecting-ip": ip, ...(init.headers as Record<string, string> | undefined) } });

	afterEach(() => vi.restoreAllMocks());

	it("HEAD seals no token and writes no event; a GET of the same page does both", async () => {
		const writes = vi.spyOn(env.EVENTS, "writeDataPoint");

		const got = await page("198.51.100.30");
		const token = metaToken(await got.text());
		expect(writes).toHaveBeenCalledTimes(1); // positive control: the spy sees the Worker's write
		expect(writes.mock.calls[0]?.[0]?.blobs?.[0]).toBe("page");

		const head = await page("198.51.100.30", { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(head.headers.get("content-type")).toContain("text/html");
		// The same per-visitor headers as the GET: no shared caching, no validator.
		expect(head.headers.get("cache-control")).toBe(got.headers.get("cache-control"));
		expect(head.headers.get("cache-control")).toBe("private, no-cache");
		expect(head.headers.get("etag")).toBeNull();
		expect(await head.text()).toBe("");
		expect(writes).toHaveBeenCalledTimes(1);
		expect(token).toHaveLength(91);
	});

	it("a real 304 from the origin passes through with private headers, no token and no event", async () => {
		// The origin's own validator, read straight from the real Static Assets binding (the
		// Worker strips it from what visitors get, so a client that still holds it is the case).
		const fromOrigin = await env.ASSETS.fetch(`${BASE}/`);
		await fromOrigin.body?.cancel();
		const etag = fromOrigin.headers.get("etag");
		expect(etag).toBeTruthy();
		expect(fromOrigin.headers.get("cache-control")).toContain("public");

		const writes = vi.spyOn(env.EVENTS, "writeDataPoint");
		await (await page("198.51.100.31")).text();
		expect(writes).toHaveBeenCalledTimes(1); // positive control

		const notModified = await page("198.51.100.31", { headers: { "if-none-match": etag ?? "" } });
		expect(notModified.status).toBe(304);
		expect(notModified.headers.get("cache-control")).toBe("private, no-cache");
		expect(notModified.headers.get("etag")).toBeNull();
		expect(await notModified.text()).toBe("");
		expect(writes).toHaveBeenCalledTimes(1);
	});

	it("in front of a real origin (no ASSETS binding), an origin's no-store survives and the page is still tokenized", async () => {
		// Production path: without ASSETS the Worker forwards with fetch(request). Mock only the
		// origin, as the Vitest integration recommends for outbound requests, and fail on anything else.
		// Django's never_cache header: what an account page actually sends.
		const accountPage = "<!doctype html><html><head><title>Your account</title></head><body><h1>Orders</h1></body></html>";
		const origin = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
			const req = new Request(input, init);
			if (req.url === `${BASE}/account`) {
				return new Response(accountPage, {
					headers: {
						"content-type": "text/html; charset=utf-8",
						"cache-control": "max-age=0, no-cache, no-store, must-revalidate, private",
						etag: '"account-v1"',
						"content-length": String(accountPage.length),
					},
				});
			}
			throw new Error(`unexpected outbound request: ${req.method} ${req.url}`);
		});
		const writes = vi.spyOn(env.EVENTS, "writeDataPoint");

		const ctx = createExecutionContext();
		const res = await worker.fetch(
			new Request(`${BASE}/account`, { headers: { "cf-connecting-ip": "198.51.100.32" } }) as Request<unknown, IncomingRequestCfProperties>,
			{ ...env, ASSETS: undefined } as unknown as Env,
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(origin).toHaveBeenCalledTimes(1);
		expect(res.headers.get("cache-control")).toBe("private, no-store");
		expect(res.headers.get("etag")).toBeNull();
		expect(res.headers.get("content-length")).toBeNull(); // the body grew
		const token = metaToken(await res.text());
		expect(writes).toHaveBeenCalledTimes(1);

		// The token is genuine and names the requester: decode it with the real key ring.
		const decoded = await admin("/decode", { method: "POST", body: JSON.stringify({ token }) });
		const body = (await decoded.json()) as { valid: number; results: { fingerprint: { ip: string } }[] };
		expect(body.valid).toBe(1);
		expect(body.results[0]?.fingerprint.ip).toBe("198.51.100.32");
	});
});

describe("approval-gated honeypot", () => {
	it("trap hit creates only a PENDING flag; decoy starts after approval", async () => {
		const ip = "203.0.113.50";
		const trap = await get("/catalog/full-export", ip);
		expect(await trap.text()).toContain("Catalog export");

		const pending = await eventually(() =>
			env.DB.prepare("SELECT status FROM flags WHERE indicator = ?").bind(`ip:${ip}`).first<{ status: string }>(),
		);
		expect(pending.status).toBe("pending");

		// Still the real page while pending.
		expect(await (await get("/", ip)).text()).toContain("Gear notes from the trail");

		const approved = await admin("/flags/approve", { method: "POST", body: JSON.stringify({ indicators: [`ip:${ip}`] }) });
		expect(((await approved.json()) as { data: { approved: unknown[] } }).data.approved).toHaveLength(1);

		const decoy = await (await get("/", ip)).text();
		expect(decoy).toContain("Catalog export");
		expect(decoy).toMatch(/csrf-token" content="[A-Za-z0-9_-]{91}"/); // decoys are attributable too

		const removed = await admin(`/flags/${encodeURIComponent(`ip:${ip}`)}`, { method: "DELETE" });
		expect(removed.status).toBe(200);
		expect(await (await get("/", ip)).text()).toContain("Gear notes from the trail");
	});

	it("never enforces on a verified bot, even when its IP is flagged", async () => {
		const ip = "203.0.113.52";
		await admin("/flags", { method: "POST", body: JSON.stringify({ ip, action: "block", reason: "test" }) });
		const asBot = (cf: Record<string, unknown>) =>
			exports.default.fetch(new Request(`${BASE}/`, { headers: { "cf-connecting-ip": ip }, cf } as RequestInit));
		expect((await get("/", ip)).status).toBe(403); // a normal client from that IP is blocked
		for (const cf of [{ botManagement: { verifiedBot: true, score: 99 } }, { verifiedBotCategory: "Search Engine Crawler" }]) {
			const res = await asBot(cf);
			expect(res.status).toBe(200);
			expect(await res.text()).toContain("Gear notes from the trail");
		}
		await admin(`/flags/${encodeURIComponent(`ip:${ip}`)}`, { method: "DELETE" });
	});

	it("seals either verified-bot signal into the token (so case decisions can skip it)", async () => {
		for (const cf of [{ botManagement: { verifiedBot: true, score: 99 } }, { verifiedBotCategory: "Search Engine Crawler" }]) {
			const html = await (await exports.default.fetch(new Request(`${BASE}/`, { headers: { "cf-connecting-ip": "203.0.113.53" }, cf } as RequestInit))).text();
			const res = await admin("/decode", { method: "POST", body: JSON.stringify({ token: metaToken(html) }) });
			const body = (await res.json()) as { results: { fingerprint: { verifiedBot: boolean } }[] };
			expect(body.results[0]?.fingerprint.verifiedBot).toBe(true);
		}
	});

	it("manual block flag returns 403 from the Worker fallback", async () => {
		const ip = "203.0.113.51";
		const res = await admin("/flags", { method: "POST", body: JSON.stringify({ ip, action: "block", reason: "test" }) });
		const body = (await res.json()) as { waf: string };
		expect(body.waf).toBe("skipped"); // no CF_API_TOKEN / WAF_LIST_ID in tests
		expect((await get("/", ip)).status).toBe(403);
		await admin(`/flags/${encodeURIComponent(`ip:${ip}`)}`, { method: "DELETE" });
	});
});

describe("Cloudflare IP protection", () => {
	it("never flags a trap hit from a Cloudflare IP", async () => {
		const ip = "104.16.0.10";
		await (await get("/catalog/full-export", ip)).text();
		await scheduler.wait(150);
		const row = await env.DB.prepare("SELECT 1 FROM flags WHERE indicator = ?").bind(`ip:${ip}`).first();
		expect(row).toBeNull();
	});

	it("refuses manual flags for Cloudflare IPs", async () => {
		const res = await admin("/flags", { method: "POST", body: JSON.stringify({ ip: "2606:4700::1111", action: "block" }) });
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error).toContain("Cloudflare IP");
	});
});

describe("beacon", () => {
	it("a valid token reported from a foreign host creates a pending lead", async () => {
		const token = metaToken(await (await get("/", "198.51.100.30")).text());
		const res = await exports.default.fetch(`${BASE}/api/rum`, {
			method: "POST",
			body: JSON.stringify({ t: token, u: "https://clone.example/products?x=1" }),
			headers: { "cf-connecting-ip": "192.0.2.200", "content-type": "text/plain" },
		});
		expect(res.status).toBe(204);
		const lead = await eventually(() =>
			env.DB.prepare("SELECT * FROM leads WHERE host = ?")
				.bind("clone.example")
				.first<{ status: string; source: string; sample_url: string; token: string; token_ip: string }>(),
		);
		expect(lead).toMatchObject({ status: "pending", source: "beacon", sample_url: "https://clone.example/products" });
		// The lead keeps the scraper's token (who fetched the page), never the beacon sender's IP.
		expect(lead.token).toBe(token);
		expect(lead.token_ip).toBe("198.51.100.30");
		expect(JSON.stringify(lead)).not.toContain("192.0.2.200");
	});

	it("ignores invalid tokens and canonical hosts", async () => {
		for (const body of [
			{ t: "x".repeat(91), u: "https://forged.example/" },
			{ t: "", u: "https://honeypot.automatic-demo.com/" },
		]) {
			const res = await exports.default.fetch(`${BASE}/api/rum`, { method: "POST", body: JSON.stringify(body) });
			expect(res.status).toBe(204);
		}
		await scheduler.wait(100);
		const row = await env.DB.prepare("SELECT 1 FROM leads WHERE host = ?").bind("forged.example").first();
		expect(row).toBeNull();
	});

	it("forged invalid beacons can't use up a real clone host's budget", async () => {
		const host = "budget-clone.example";
		// More invalid reports for the host than BEACON_LIMITER allows per minute (10), no Origin header.
		for (let i = 0; i < 12; i++) {
			const res = await exports.default.fetch(`${BASE}/api/rum`, { method: "POST", body: JSON.stringify({ t: "y".repeat(91), u: `https://${host}/` }) });
			expect(res.status).toBe(204);
		}
		const token = metaToken(await (await get("/", "198.51.100.31")).text());
		await exports.default.fetch(`${BASE}/api/rum`, { method: "POST", body: JSON.stringify({ t: token, u: `https://${host}/page` }) });
		const lead = await eventually(() => env.DB.prepare("SELECT * FROM leads WHERE host = ?").bind(host).first<{ token: string }>());
		expect(lead.token).toBe(token);
	});
});

describe("admin surface", () => {
	it("returns 404 without a valid bearer token", async () => {
		expect((await exports.default.fetch(`${BASE}/__hp/flags`)).status).toBe(404);
		const wrong = await exports.default.fetch(`${BASE}/__hp/flags`, { headers: { authorization: "Bearer nope" } });
		expect(wrong.status).toBe(404);
	});

	it("refuses to investigate the canonical host", async () => {
		const res = await admin("/cases", { method: "POST", body: JSON.stringify({ url: `${BASE}/` }) });
		expect(res.status).toBe(400);
	});
});
