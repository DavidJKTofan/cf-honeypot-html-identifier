import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/core/config";
import { collectSignals } from "../src/identity/fingerprint";
import { noteForeignReferer } from "../src/honeypot/trap";

function capture() {
	const points: { blobs?: unknown[] }[] = [];
	const fakeEnv = { ...env, EVENTS: { writeDataPoint: (p: { blobs?: unknown[] }) => points.push(p) } } as unknown as Env;
	return { fakeEnv, points };
}

const req = (headers: Record<string, string>) =>
	new Request("https://honeypot.automatic-demo.com/article", { headers: { "cf-connecting-ip": "198.51.100.9", ...headers } });

describe("foreign Referer → hotlink events", () => {
	const cfg = loadConfig(env);

	it("ignores link clicks (navigations) from other sites", () => {
		const { fakeEnv, points } = capture();
		noteForeignReferer(fakeEnv, cfg, collectSignals(req({ referer: "https://blog.example/post", "sec-fetch-dest": "document" })), false);
		expect(points).toHaveLength(0);
	});

	it("records subresource loads (hotlinked script/image) from foreign pages", () => {
		const { fakeEnv, points } = capture();
		noteForeignReferer(fakeEnv, cfg, collectSignals(req({ referer: "https://clone.example/", "sec-fetch-dest": "script" })), false);
		expect(points).toHaveLength(1);
		expect(points[0]?.blobs?.[0]).toBe("hotlink");
	});

	it("never stores anything that identifies the clone's visitor", () => {
		const { fakeEnv, points } = capture();
		const s = collectSignals(
			req({
				referer: "https://clone.example/page",
				"sec-fetch-dest": "style",
				"user-agent": "Mozilla/5.0 (Visitor Browser)",
				"accept-language": "de-DE",
				"cf-ray": "a5fbe829fda7b263-DUS",
			}),
		);
		noteForeignReferer(fakeEnv, cfg, s, true);
		const blobs = points[0]?.blobs ?? [];
		// blob4 ip, blob5 UA, blob6 JA4, blob11 city, blob15 Accept-Language, blob18 Ray ID: all empty.
		for (const i of [3, 4, 5, 10, 14, 17]) expect(blobs[i]).toBe("");
		expect(JSON.stringify(points[0])).not.toContain("198.51.100.9");
		// What describes the clone is kept: our path, the clone page, the clone host.
		expect(blobs[2]).toBe("/article");
		expect(blobs[13]).toBe("https://clone.example/page");
		expect(blobs[18]).toBe("clone.example");
	});

	it("without Sec-Fetch-Dest, counts only static assets / the beacon script", () => {
		const { fakeEnv, points } = capture();
		noteForeignReferer(fakeEnv, cfg, collectSignals(req({ referer: "https://clone.example/" })), false);
		noteForeignReferer(fakeEnv, cfg, collectSignals(req({ referer: "https://clone.example/" })), true);
		expect(points).toHaveLength(1);
	});

	it("ignores canonical hosts and benign proxies", () => {
		const { fakeEnv, points } = capture();
		for (const referer of ["https://honeypot.automatic-demo.com/", "https://www-example-com.translate.goog/", "https://www.google.com/"]) {
			noteForeignReferer(fakeEnv, cfg, collectSignals(req({ referer, "sec-fetch-dest": "image" })), true);
		}
		expect(points).toHaveLength(0);
	});
});
