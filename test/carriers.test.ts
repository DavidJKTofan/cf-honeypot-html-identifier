import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { beaconScript } from "../src/honeypot/beacon";
import { decodeCharRefs, injectCarriers, scanHtml } from "../src/identity/carriers";
import { loadConfig, type Config } from "../src/core/config";
import { importTokenKey, sealToken, tokenToBytes } from "../src/identity/token";
import { decodeZeroWidth, encodeZeroWidth, findZeroWidthTokens } from "../src/identity/zerowidth";

const PAGE = `<!doctype html><html><head><title>t</title></head><body>
<p>First paragraph with words.</p><form action="/x"><input name="q"></form><p>Second.</p></body></html>`;

function cfg(carriers: string): Config {
	return loadConfig({ ...env, CARRIERS: carriers });
}

async function token(): Promise<string> {
	return sealToken(
		{ issuedAt: 1, ip: "192.0.2.1", asn: 1, country: "US", colo: "SJC", botScore: null, verifiedBot: false, jsDetectionPassed: false, botManagement: false, rayId: "0123456789abcdef" },
		await importTokenKey(env.TOKEN_KEY),
	);
}

async function rewrite(html: string, c: Config, t: string): Promise<{ text: string; headers: Headers }> {
	const res = injectCarriers(new Response(html, { headers: { "content-type": "text/html", etag: '"abc"' } }), {
		token: t,
		cfg: c,
		origin: "https://honeypot.automatic-demo.com",
	});
	return { text: await res.text(), headers: res.headers };
}

describe("zero-width encoding", () => {
	it("round-trips bytes", async () => {
		const bytes = tokenToBytes(await token()) as Uint8Array;
		const zw = encodeZeroWidth(bytes);
		expect(zw).toHaveLength(272);
		expect(zw.trim()).toHaveLength(272); // survives String.trim()
		expect(decodeZeroWidth(zw)).toEqual(bytes);
		expect(findZeroWidthTokens(`abc${zw}def`)).toHaveLength(1);
	});
});

describe("carrier injection and extraction", () => {
	it("injects meta, trap link and beacon script by default and strips cache validators", async () => {
		const t = await token();
		const { text, headers } = await rewrite(PAGE, cfg("meta,trap,beacon"), t);
		expect(text).toContain(`<meta name="csrf-token" content="${t}">`);
		expect(text).toMatch(/<a href="\/catalog\/full-export" rel="nofollow" hidden aria-hidden="true" tabindex="-1">/);
		expect(text).toContain('<script src="https://honeypot.automatic-demo.com/assets/js/rum.js" defer></script>');
		expect(text).not.toContain("​‌");
		expect(headers.get("cache-control")).toBe("private, no-cache");
		expect(headers.get("etag")).toBeNull();
	});

	it("extracts the same token from every enabled carrier", async () => {
		const c = cfg("meta,trap,beacon,zw,form");
		const t = await token();
		const { text } = await rewrite(PAGE, c, t);
		const scan = await scanHtml(text, c);
		expect(new Set(scan.tokens.map((x) => x.token))).toEqual(new Set([t]));
		expect(scan.tokens.map((x) => x.carrier).sort()).toEqual(["meta"]); // deduped by token, first carrier wins
		expect(scan.beaconScript).toBe(true);
		expect(scan.trapLink).toBe(true);

		// Text-only scrape: markup gone, zero-width run survives.
		const textOnly = text.replace(/<[^>]+>/g, " ");
		const fromText = await scanHtml(`<p>${textOnly}</p>`, c);
		expect(fromText.tokens).toEqual([{ carrier: "zw", token: t }]);
	});

	it("finds a token even if the cloner renamed the meta tag", async () => {
		const t = await token();
		const scan = await scanHtml(`<html><head><meta name="x-build" content="${t}"></head></html>`, cfg("meta"));
		expect(scan.tokens).toEqual([{ carrier: "attr:meta[content]", token: t }]);
	});

	it("never shadows a real CSRF meta tag: uses the fallback name instead", async () => {
		const t = await token();
		const page = `<html><head><meta name="csrf-token" content="REAL-RAILS-TOKEN"></head><body><p>x</p></body></html>`;
		const { text } = await rewrite(page, cfg("meta"), t);
		expect(text).toContain('<meta name="csrf-token" content="REAL-RAILS-TOKEN">');
		expect(text).toContain(`<meta name="request-id" content="${t}">`);
		expect(text.match(/name="csrf-token"/g)).toHaveLength(1);
		expect((await scanHtml(text, cfg("meta"))).tokens).toEqual([{ carrier: "meta-fallback", token: t }]);
	});

	it("adds the form field exactly once to a form that does not have one", async () => {
		const t = await token();
		const { text } = await rewrite(`<html><body><form method="post"><input name="q"></form></body></html>`, cfg("form"), t);
		expect(text.match(/name="_csrf"/g)).toHaveLength(1);
		expect(text).toContain(`<input name="q"><input type="hidden" name="_csrf" value="${t}"></form>`);
		expect((await scanHtml(text, cfg("form"))).tokens).toEqual([{ carrier: "form", token: t }]);
	});

	it("never shadows a real _csrf field (Spring, csurf): uses the fallback name instead", async () => {
		const t = await token();
		const page = `<html><body>
<form method="post"><input type="hidden" name="_csrf" value="REAL"><input name="q"></form>
<form method="post"><input name="other"></form></body></html>`;
		const { text } = await rewrite(page, cfg("form"), t);
		expect(text.match(/name="_csrf"/g)).toHaveLength(2); // the real one, plus ours in the second form only
		expect(text).toContain(`<input type="hidden" name="_csrf" value="REAL"><input name="q"><input type="hidden" name="request_id" value="${t}"></form>`);
		expect(text).toContain(`<input name="other"><input type="hidden" name="_csrf" value="${t}"></form>`);
		const carriers = (await scanHtml(text, cfg("form"))).tokens.map((x) => x.carrier);
		expect(carriers).toEqual(["form-fallback"]); // deduped by token, first carrier wins
	});

	it("handles a form without an end tag without crashing or duplicating", async () => {
		const t = await token();
		const { text } = await rewrite(`<html><body><form method="post"><input name="q"><p>unclosed`, cfg("form"), t);
		expect((text.match(/name="_csrf"/g) ?? []).length).toBeLessThanOrEqual(1);
		expect(text).toContain("unclosed");
	});

	it("falls back when the document has no <head>", async () => {
		const t = await token();
		const { text } = await rewrite("<div>fragment</div>", cfg("meta"), t);
		expect(text).toContain(`content="${t}"`);
	});
});

describe("scanner sees what a browser sees (entity-encoded and padded tokens)", () => {
	it("decodes numeric and named character references", () => {
		expect(decodeCharRefs("&#100;g&#x43;j&lowbar;x&amp;y")).toBe("dgCj_x&y");
		expect(decodeCharRefs("&#100gCj")).toBe("dgCj");
		expect(decodeCharRefs("plain")).toBe("plain");
		expect(decodeCharRefs("&#0;&#xD800;&unknownref;")).toBe("&#0;&#xD800;&unknownref;");
	});

	it("finds a token with one entity-encoded character (browsers and the beacon decode it)", async () => {
		const t = await token();
		const encoded = `&#${t.charCodeAt(0)};${t.slice(1, 40)}&#x${t.charCodeAt(40).toString(16)};${t.slice(41)}`;
		const scan = await scanHtml(`<html><head><meta name="csrf-token" content="${encoded}"></head><body></body></html>`, cfg("meta"));
		expect(scan.tokens.map((x) => x.token)).toEqual([t]);
		expect(scan.tokens[0]?.carrier).toBe("meta");
	});

	it("finds a whitespace-padded token", async () => {
		const t = await token();
		const scan = await scanHtml(`<html><head><meta name="csrf-token" content="  ${t}\n"></head><body></body></html>`, cfg("meta"));
		expect(scan.tokens.map((x) => x.token)).toEqual([t]);
	});
});

describe("beacon script", () => {
	it("trims the meta value before matching (padded tokens still beacon)", () => {
		expect(beaconScript("https://honeypot.automatic-demo.com", cfg("beacon"))).toContain('.getAttribute("content")||"").trim()');
	});

	it("does not contain canonical hosts or the endpoint in plain text", () => {
		const js = beaconScript("https://honeypot.automatic-demo.com", cfg("beacon"));
		expect(js).not.toContain("honeypot.automatic-demo.com");
		expect(js).not.toContain("/api/rum");
		expect(js).toContain("sendBeacon");
	});
});
