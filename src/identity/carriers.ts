/**
 * Carriers: where the sealed token hides inside HTML, injected with the
 * streaming HTMLRewriter (no full-body buffering), plus the matching extractor.
 * https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/
 */
import type { Config } from "../core/config";
import { tokenToBytes, TOKEN_PATTERN } from "./token";
import { escapeAttr } from "../core/util";
import { encodeZeroWidth, findZeroWidthTokens, isZeroWidthChar, ZW_LENGTH } from "./zerowidth";

/** Used instead of META_NAME when the page already has a meta tag with that name (e.g. a real Rails/Laravel CSRF token). */
export const META_FALLBACK_NAME = "request-id";

/** Used instead of FORM_FIELD when a form already has a control with that name (e.g. a real Spring or csurf `_csrf` field). */
export const FORM_FALLBACK_NAME = "request_id";

export interface InjectOptions {
	token: string;
	cfg: Config;
	/** Origin that serves the beacon script (the canonical site). */
	origin: string;
}

/** Rewrites an HTML response; handler state is created per call (never global). */
export function injectCarriers(response: Response, { token, cfg, origin }: InjectOptions): Response {
	const c = cfg.carriers;
	const metaTag = (name: string) => `<meta name="${escapeAttr(name)}" content="${token}">`;
	const meta = metaTag(cfg.metaName);
	// `meta`: the tag is in the output. `headOpen`: a <head> start tag was seen, so the tag is due
	// at its end tag. lol-html only calls onEndTag for a literal </head>, and HTML allows omitting it
	// (minifiers do), so <body>, then the document end, insert the tag if </head> never came.
	const state = { meta: !c.has("meta"), headOpen: false, zw: !c.has("zw"), body: false, collision: false };

	const tail: string[] = [];
	if (c.has("trap")) {
		// `hidden` (not inline CSS) keeps the link invisible even under a strict CSP.
		tail.push(
			`<a href="${escapeAttr(cfg.trapPath)}" rel="nofollow" hidden aria-hidden="true" tabindex="-1">Full catalog export</a>`,
		);
	}
	if (c.has("beacon")) {
		// Absolute URL: a clone either hotlinks it (foreign Referer) or copies it (then it beacons).
		tail.push(`<script src="${escapeAttr(origin + cfg.beaconScriptPath)}" defer></script>`);
	}

	const rewriter = new HTMLRewriter();
	if (c.has("meta")) {
		// Never shadow a real token: if the page already has <meta name=META_NAME>, use the fallback name.
		rewriter.on(`meta[name="${cfg.metaName.replace(/"/g, "")}"]`, {
			element() {
				state.collision = true;
			},
		});
		rewriter.on("head", {
			element(el) {
				if (state.meta || state.headOpen) return;
				state.headOpen = true;
				el.onEndTag((end) => {
					if (state.meta) return;
					end.before(state.collision ? metaTag(META_FALLBACK_NAME) : meta, { html: true });
					state.meta = true;
				});
			},
		});
	}
	const pendingMeta = () => (state.collision ? metaTag(META_FALLBACK_NAME) : meta);
	rewriter.on("body", {
		element(el) {
			if (state.body) return;
			state.body = true;
			if (!state.meta) {
				el.prepend(pendingMeta(), { html: true });
				state.meta = true;
			}
			if (tail.length > 0) el.append(tail.join(""), { html: true });
		},
	});
	if (c.has("zw")) {
		const bytes = tokenToBytes(token);
		const zw = bytes ? encodeZeroWidth(bytes) : "";
		rewriter.on("p", {
			text(chunk) {
				if (state.zw || !zw || chunk.text.trim().length === 0) return;
				chunk.after(zw); // plain text, HTML-escaped by default
				state.zw = true;
			},
		});
	}
	if (c.has("form")) {
		// Never shadow a real field: Spring Security and Express csurf both post `_csrf`, and a
		// second field with that name breaks their validation. The insert waits for </form>, by
		// which point we know whether the form already had a FORM_FIELD control; if it did, the
		// token goes into FORM_FALLBACK_NAME instead. A form without an end tag gets nothing
		// (the end-tag handler never runs), which is safe: no duplicate and no broken markup.
		const input = (name: string) => `<input type="hidden" name="${escapeAttr(name)}" value="${token}">`;
		let openForm: { hasField: boolean } | null = null;
		rewriter.on("form", {
			element(el) {
				const form = { hasField: false };
				openForm = form;
				el.onEndTag((end) => {
					end.before(input(form.hasField ? FORM_FALLBACK_NAME : cfg.formField), { html: true });
					if (openForm === form) openForm = null;
				});
			},
		});
		rewriter.on(`form [name="${cfg.formField.replace(/["\\]/g, "")}"]`, {
			element() {
				if (openForm) openForm.hasField = true;
			},
		});
	}
	rewriter.onDocument({
		end(end) {
			if (!state.meta) end.append(pendingMeta(), { html: true });
		},
	});

	const out = rewriter.transform(response);
	const headers = new Headers(out.headers);
	// The body is now per-visitor: never let a shared cache serve it to someone else.
	headers.set("cache-control", "private, no-cache");
	headers.delete("etag");
	headers.delete("content-length");
	return new Response(out.body, { status: out.status, statusText: out.statusText, headers });
}

export interface FoundToken {
	carrier: string;
	token: string;
}

export interface ScanResult {
	tokens: FoundToken[];
	beaconScript: boolean;
	trapLink: boolean;
}

/** Named references that can produce base64url characters or common attribute punctuation. */
const NAMED_REFS: Record<string, string> = {
	amp: "&",
	lt: "<",
	gt: ">",
	quot: '"',
	apos: "'",
	lowbar: "_",
	UnderBar: "_",
	equals: "=",
	plus: "+",
	sol: "/",
	period: ".",
	nbsp: " ",
};

/**
 * Decode HTML character references in an attribute value the way a browser does.
 * HTMLRewriter (lol-html) returns attribute values raw, so `content="&#100;gCj…"` would
 * not match the token pattern here, while the browser (and the beacon) see a valid token.
 * Decoding closes that asymmetry. Over-decoding is harmless: a wrong string just fails
 * AES-GCM.
 */
export function decodeCharRefs(value: string): string {
	if (!value.includes("&")) return value;
	return value.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([A-Za-z][A-Za-z0-9]{1,31}));?/g, (m, dec?: string, hex?: string, name?: string) => {
		if (dec !== undefined || hex !== undefined) {
			const cp = dec !== undefined ? Number.parseInt(dec, 10) : Number.parseInt(hex ?? "", 16);
			return cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : m;
		}
		return (name && NAMED_REFS[name]) ?? m;
	});
}

/** Name the carrier a token-shaped attribute came from (our own names first, then a generic label). */
function carrierLabel(tag: string, elementName: string | null, attr: string, cfg: Pick<Config, "metaName" | "formField">): string {
	if (tag === "meta" && elementName === cfg.metaName) return "meta";
	if (tag === "meta" && elementName === META_FALLBACK_NAME) return "meta-fallback";
	if (tag === "input" && elementName === cfg.formField) return "form";
	if (tag === "input" && elementName === FORM_FALLBACK_NAME) return "form-fallback";
	return `attr:${tag}[${attr}]`;
}

/**
 * Extract every candidate token from a page: any attribute value shaped like a
 * token (catches renamed meta tags too) plus zero-width runs in text. Attribute
 * values are entity-decoded and trimmed first, so a copy that encodes one character
 * (`&#100;`) or pads the value still yields the token a browser would see.
 */
export async function scanHtml(
	source: Response | string,
	cfg: Pick<Config, "metaName" | "formField" | "beaconScriptPath" | "trapPath">,
): Promise<ScanResult> {
	// Deliberately unbounded (the input is: captures keep 2 MiB): capping candidates in document
	// order would let a clone hide the real token behind junk token-shaped values. The
	// Workflow caps *valid* tokens instead (MAX_CASE_TOKENS), which cost a page load each.
	const found = new Map<string, FoundToken>();
	const result: ScanResult = { tokens: [], beaconScript: false, trapLink: false };
	const add = (carrier: string, token: string) => {
		if (!found.has(token)) found.set(token, { carrier, token });
	};

	let run = "";
	const flush = () => {
		if (run.length >= ZW_LENGTH) for (const t of findZeroWidthTokens(run)) add("zw", t);
		run = "";
	};

	const response =
		typeof source === "string"
			? new Response(source, { headers: { "content-type": "text/html; charset=utf-8" } })
			: source;

	const rewriter = new HTMLRewriter()
		.on("*", {
			element(el) {
				const tag = el.tagName.toLowerCase();
				for (const attr of el.attributes) {
					const name = attr[0] ?? "";
					const value = decodeCharRefs(attr[1] ?? "").trim();
					if (TOKEN_PATTERN.test(value)) add(carrierLabel(tag, decodeCharRefs(el.getAttribute("name") ?? ""), name, cfg), value);
					if (name === "src" && value.includes(cfg.beaconScriptPath)) result.beaconScript = true;
					if (name === "href" && value.includes(cfg.trapPath)) result.trapLink = true;
				}
			},
		})
		.onDocument({
			text(chunk) {
				const text = chunk.text;
				for (let i = 0; i < text.length; i++) {
					const ch = text.charAt(i);
					if (isZeroWidthChar(ch)) run += ch;
					else if (run) flush();
				}
			},
			end() {
				flush();
			},
		});

	// Drive the stream to completion; output is discarded.
	await rewriter.transform(response).arrayBuffer();
	result.tokens = [...found.values()];
	return result;
}
