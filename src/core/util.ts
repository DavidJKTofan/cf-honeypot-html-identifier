/**
 * Small shared helpers. No module-level mutable state (Workers reuse isolates
 * across requests): https://developers.cloudflare.com/workers/best-practices/workers-best-practices/
 */

const B64URL = /^[A-Za-z0-9_-]*$/;

export function b64urlEncode(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(input: string): Uint8Array | null {
	if (!B64URL.test(input)) return null;
	const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
	try {
		const bin = atob(input.replace(/-/g, "+").replace(/_/g, "/") + pad);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	} catch {
		return null;
	}
}

export function b64Decode(input: string): Uint8Array | null {
	try {
		const bin = atob(input.trim());
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	} catch {
		return null;
	}
}

export function hex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomHex(byteLength: number): string {
	return hex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function sha256Hex(data: ArrayBuffer | Uint8Array | string): Promise<string> {
	const buf = typeof data === "string" ? new TextEncoder().encode(data) : data;
	return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", buf)));
}

/** Constant-time string comparison (hash first so lengths always match). */
export async function timingSafeEqualStr(a: string, b: string): Promise<boolean> {
	const enc = new TextEncoder();
	const [ha, hb] = await Promise.all([
		crypto.subtle.digest("SHA-256", enc.encode(a)),
		crypto.subtle.digest("SHA-256", enc.encode(b)),
	]);
	return crypto.subtle.timingSafeEqual(ha, hb);
}

type Level = "info" | "warn" | "error";

/** Structured JSON logs for Workers Logs. */
export function log(level: Level, message: string, fields: Record<string, unknown> = {}): void {
	const line = JSON.stringify({ level, message, ...fields });
	if (level === "error") console.error(line);
	else if (level === "warn") console.warn(line);
	else console.log(line);
}

export function errorMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

export function json(data: unknown, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set("content-type", "application/json; charset=utf-8");
	headers.set("cache-control", "no-store");
	return new Response(JSON.stringify(data, null, 2), { ...init, headers });
}

export function notFound(): Response {
	return new Response("Not Found", { status: 404, headers: { "content-type": "text/plain" } });
}

export class BodyTooLargeError extends Error {}

/** Read a stream fully, aborting once `maxBytes` is exceeded. */
export async function readStreamLimited(
	body: ReadableStream<Uint8Array> | null,
	maxBytes: number,
): Promise<Uint8Array> {
	if (!body) return new Uint8Array();
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel();
			throw new BodyTooLargeError(`body exceeds ${maxBytes} bytes`);
		}
		chunks.push(value);
	}
	const out = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		out.set(c, offset);
		offset += c.byteLength;
	}
	return out;
}

/** Parse a JSON request body with a size cap (best practice: bound before reading). */
export async function readJson<T>(request: Request, maxBytes = 1_000_000): Promise<T | null> {
	const declared = Number(request.headers.get("content-length") ?? "0");
	if (declared > maxBytes) throw new BodyTooLargeError(`body exceeds ${maxBytes} bytes`);
	const bytes = await readStreamLimited(request.body, maxBytes);
	if (bytes.byteLength === 0) return null;
	try {
		return JSON.parse(new TextDecoder().decode(bytes)) as T;
	} catch {
		return null;
	}
}

export function nowSec(): number {
	return Math.floor(Date.now() / 1000);
}

/** True if `host` equals or is a subdomain of any suffix in the list. */
export function hostMatchesSuffix(host: string, suffixes: readonly string[]): boolean {
	const h = host.toLowerCase();
	return suffixes.some((s) => h === s || h.endsWith(`.${s}`));
}

export function safeUrl(input: string | null | undefined): URL | null {
	if (!input) return null;
	try {
		const u = new URL(input);
		return u.protocol === "http:" || u.protocol === "https:" ? u : null;
	} catch {
		return null;
	}
}

const STATIC_EXT =
	/\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|pdf|zip|gz|wasm)$/i;

/** Static assets skip all honeypot logic (no storage I/O). */
export function isStaticAsset(request: Request, url: URL): boolean {
	const cf = request.cf as { botManagement?: { staticResource?: boolean } } | undefined;
	return cf?.botManagement?.staticResource === true || STATIC_EXT.test(url.pathname);
}

export function isHtmlResponse(response: Response): boolean {
	return (response.headers.get("content-type") ?? "").toLowerCase().includes("text/html");
}

export function truncate(value: string | null | undefined, max: number): string {
	if (!value) return "";
	return value.length > max ? value.slice(0, max) : value;
}

/** Escape a value for use inside a double-quoted HTML attribute. */
export function escapeAttr(value: string): string {
	return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function escapeHtml(value: string): string {
	return escapeAttr(value).replace(/'/g, "&#39;");
}

/** Uniform random integer in [0, max) from Web Crypto (never Math.random). */
export function randomInt(max: number): number {
	if (max <= 1) return 0;
	const buf = crypto.getRandomValues(new Uint32Array(1));
	return (buf[0] ?? 0) % max;
}
