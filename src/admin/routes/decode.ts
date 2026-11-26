/** GET /whoami · POST /decode {token | html | html_b64 | url} */
import { loadSealingKey, sealToken } from "../../identity/token";
import { collectSignals } from "../../identity/fingerprint";
import { scanHtml, type ScanResult } from "../../identity/carriers";
import { json, readJson, safeUrl } from "../../core/util";
import { badRequest, type AdminRoute } from "../context";
import { decodeTokens, describeErrorPage, fetchPage } from "../decode";

interface DecodeBody {
	token?: string;
	html?: string;
	/** Base64 HTML: pasted pages contain <script> etc. that WAF managed rules may block in plain JSON. */
	html_b64?: string;
	url?: string;
}

function fromBase64(b64: string): string | null {
	try {
		const bin = atob(b64.replace(/\s+/g, ""));
		return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
	} catch {
		return null;
	}
}

export const decodeRoutes: AdminRoute = async ({ request, env, cfg, method, path, actor }) => {
	if (method === "GET" && path === "/whoami") {
		const s = collectSignals(request);
		return json({ actor, auth: cfg.access ? "access" : "bearer", token: await sealToken(s, await loadSealingKey(env)), fingerprint: s });
	}
	if (method !== "POST" || path !== "/decode") return null;

	const body = await readJson<DecodeBody>(request);
	if (!body) return badRequest("expected JSON body with token, html, html_b64 or url");
	let source: "token" | "html" | "url";
	let scan: ScanResult;
	let fetched: Record<string, unknown> | undefined;
	if (typeof body.token === "string") {
		source = "token";
		scan = { tokens: [{ carrier: "token", token: body.token.trim() }], beaconScript: false, trapLink: false };
	} else if (typeof body.html === "string" || typeof body.html_b64 === "string") {
		source = "html";
		const html = typeof body.html === "string" ? body.html : fromBase64(body.html_b64 ?? "");
		if (html === null) return badRequest("html_b64 is not valid base64");
		scan = await scanHtml(html, cfg);
	} else if (typeof body.url === "string" && safeUrl(body.url)) {
		source = "url";
		const page = await fetchPage(body.url, undefined, undefined, cfg.captureUserAgent);
		const errorPage = describeErrorPage(page);
		fetched = {
			status: page.status,
			finalUrl: page.finalUrl,
			contentType: page.contentType,
			sha256: page.sha256,
			bytes: page.bytes.byteLength,
			truncated: page.truncated,
			...(errorPage ? { error: { ...errorPage, note: `HTTP ${page.status}: no page was served, so a missing token proves nothing` } } : {}),
		};
		scan = await scanHtml(new TextDecoder().decode(page.bytes), cfg);
	} else {
		return badRequest("provide one of: token, html, html_b64, url (absolute http/https)");
	}
	const results = await decodeTokens(env, scan.tokens, { enrich: true });
	return json({
		source,
		fetched,
		markers: { beaconScript: scan.beaconScript, trapLink: scan.trapLink, candidates: scan.tokens.length },
		valid: results.filter((r) => r.valid).length,
		results,
	});
};
