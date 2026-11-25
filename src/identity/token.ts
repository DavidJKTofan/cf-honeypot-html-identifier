/**
 * Sealed identifier ("the database is the token").
 *
 * A fixed 40-byte binary fingerprint is encrypted and authenticated with
 * AES-256-GCM (Web Crypto). Only our key can open it, so a decoded token is
 * proof that we issued that exact string for that exact request, and a
 * tampered or forged token simply fails to open.
 *
 * Layout (big-endian):
 *   0      version (1)
 *   1..4   issuedAt (uint32 unix seconds)
 *   5..20  client IP (16 bytes, IPv4 stored as IPv4-mapped IPv6)
 *   21..24 ASN (uint32)
 *   25..26 country (ASCII)
 *   27..29 colo (ASCII)
 *   30     bot score (0 = Bot Management not present)
 *   31     flags: bit0 verifiedBot, bit1 jsDetection passed, bit2 BM present
 *   32..39 Ray ID (8 bytes from 16 hex chars)
 * Sealed = IV(12) || ciphertext(40) || tag(16) = 68 bytes → 91 base64url chars.
 */
import type { Fingerprint } from "./fingerprint";
import { b64Decode, b64urlDecode, b64urlEncode } from "../core/util";

export const TOKEN_VERSION = 1;
export const PAYLOAD_LENGTH = 40;
export const IV_LENGTH = 12;
export const SEALED_LENGTH = IV_LENGTH + PAYLOAD_LENGTH + 16;
export const TOKEN_LENGTH = 91;
export const TOKEN_PATTERN = /^[A-Za-z0-9_-]{91}$/;

const AAD = new TextEncoder().encode("cf-honeypot-html-identifier/v1");

export async function importTokenKey(base64Key: string): Promise<CryptoKey> {
	const raw = b64Decode(base64Key);
	if (!raw || raw.byteLength !== 32) {
		throw new Error("TOKEN_KEY must be a base64-encoded 32-byte key (openssl rand -base64 32)");
	}
	return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** Current key first, then the optional previous key (rotation). */
export async function loadTokenKeys(env: Env): Promise<CryptoKey[]> {
	const keys = [await importTokenKey(env.TOKEN_KEY)];
	if (env.TOKEN_KEY_PREVIOUS) {
		try {
			keys.push(await importTokenKey(env.TOKEN_KEY_PREVIOUS));
		} catch {
			// Ignore a malformed previous key rather than breaking decode.
		}
	}
	return keys;
}

export async function sealToken(fp: Fingerprint, key: CryptoKey): Promise<string> {
	const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
	const ciphertext = new Uint8Array(
		await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, packFingerprint(fp)),
	);
	const sealed = new Uint8Array(SEALED_LENGTH);
	sealed.set(iv, 0);
	sealed.set(ciphertext, IV_LENGTH);
	return b64urlEncode(sealed);
}

export function tokenToBytes(token: string): Uint8Array | null {
	if (!TOKEN_PATTERN.test(token)) return null;
	const bytes = b64urlDecode(token);
	return bytes && bytes.byteLength === SEALED_LENGTH ? bytes : null;
}

export async function openToken(token: string, keys: CryptoKey[]): Promise<Fingerprint | null> {
	const sealed = tokenToBytes(token);
	if (!sealed) return null;
	const iv = sealed.slice(0, IV_LENGTH);
	const data = sealed.slice(IV_LENGTH);
	for (const key of keys) {
		try {
			const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, data);
			return unpackFingerprint(new Uint8Array(plain));
		} catch {
			// Wrong key or tampered token: try the next key.
		}
	}
	return null;
}

function ascii(value: string, length: number, pad: string): Uint8Array {
	const out = new Uint8Array(length);
	const v = (value + pad.repeat(length)).slice(0, length);
	for (let i = 0; i < length; i++) {
		const code = v.charCodeAt(i);
		out[i] = code >= 0x20 && code < 0x7f ? code : pad.charCodeAt(0);
	}
	return out;
}

export function packFingerprint(fp: Fingerprint): Uint8Array {
	const buf = new Uint8Array(PAYLOAD_LENGTH);
	const view = new DataView(buf.buffer);
	view.setUint8(0, TOKEN_VERSION);
	view.setUint32(1, fp.issuedAt >>> 0);
	buf.set(ipToBytes(fp.ip) ?? new Uint8Array(16), 5);
	view.setUint32(21, fp.asn >>> 0);
	buf.set(ascii(fp.country, 2, "X"), 25);
	buf.set(ascii(fp.colo, 3, "-"), 27);
	view.setUint8(30, fp.botScore ?? 0);
	view.setUint8(31, (fp.verifiedBot ? 1 : 0) | (fp.jsDetectionPassed ? 2 : 0) | (fp.botManagement ? 4 : 0));
	const ray = /^[0-9a-f]{16}$/i.test(fp.rayId) ? fp.rayId : "0".repeat(16);
	for (let i = 0; i < 8; i++) buf[32 + i] = Number.parseInt(ray.slice(i * 2, i * 2 + 2), 16);
	return buf;
}

export function unpackFingerprint(buf: Uint8Array): Fingerprint | null {
	if (buf.byteLength !== PAYLOAD_LENGTH) return null;
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	if (view.getUint8(0) !== TOKEN_VERSION) return null;
	const flags = view.getUint8(31);
	const score = view.getUint8(30);
	const text = (from: number, to: number) => String.fromCharCode(...buf.slice(from, to));
	return {
		issuedAt: view.getUint32(1),
		ip: bytesToIp(buf.slice(5, 21)),
		asn: view.getUint32(21),
		country: text(25, 27),
		colo: text(27, 30),
		botScore: score === 0 ? null : score,
		verifiedBot: (flags & 1) !== 0,
		jsDetectionPassed: (flags & 2) !== 0,
		botManagement: (flags & 4) !== 0,
		rayId: Array.from(buf.slice(32, 40), (b) => b.toString(16).padStart(2, "0")).join(""),
	};
}

// ---------------------------------------------------------------------------
// IP helpers (IPv4, IPv6 incl. "::" compression and embedded IPv4)
// ---------------------------------------------------------------------------

function parseIPv4(ip: string): number[] | null {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	const out: number[] = [];
	for (const p of parts) {
		if (!/^\d{1,3}$/.test(p)) return null;
		const n = Number(p);
		if (n > 255) return null;
		out.push(n);
	}
	return out;
}

export function ipToBytes(input: string): Uint8Array | null {
	const ip = input.trim().replace(/^\[|\]$/g, "").split("%")[0] ?? "";
	const v4 = parseIPv4(ip);
	if (v4) return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...v4]);
	if (!ip.includes(":")) return null;

	let head = ip;
	let tailV4: number[] = [];
	const lastColon = ip.lastIndexOf(":");
	const maybeV4 = parseIPv4(ip.slice(lastColon + 1));
	if (maybeV4) {
		tailV4 = maybeV4;
		head = ip.slice(0, lastColon + 1) + "0:0"; // placeholder groups, replaced below
	}
	const halves = head.split("::");
	if (halves.length > 2) return null;
	const toGroups = (s: string) => (s === "" ? [] : s.split(":"));
	const left = toGroups(halves[0] ?? "");
	const right = halves.length === 2 ? toGroups(halves[1] ?? "") : [];
	const missing = 8 - left.length - right.length;
	if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
	const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...right];
	if (groups.length !== 8) return null;
	const out = new Uint8Array(16);
	for (let i = 0; i < 8; i++) {
		const g = groups[i] ?? "";
		if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
		const n = Number.parseInt(g, 16);
		out[i * 2] = n >> 8;
		out[i * 2 + 1] = n & 0xff;
	}
	if (tailV4.length === 4) out.set(tailV4, 12);
	return out;
}

export function bytesToIp(b: Uint8Array): string {
	const isMapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
	if (isMapped) return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
	const groups: number[] = [];
	for (let i = 0; i < 8; i++) groups.push(((b[i * 2] ?? 0) << 8) | (b[i * 2 + 1] ?? 0));
	// RFC 5952: compress the longest run (>= 2) of zero groups.
	let bestStart = -1;
	let bestLen = 0;
	for (let i = 0; i < 8; ) {
		if (groups[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === 0) j++;
		if (j - i > bestLen && j - i >= 2) {
			bestStart = i;
			bestLen = j - i;
		}
		i = j;
	}
	const hexGroups = groups.map((g) => g.toString(16));
	if (bestStart === -1) return hexGroups.join(":");
	const left = hexGroups.slice(0, bestStart).join(":");
	const right = hexGroups.slice(bestStart + bestLen).join(":");
	return `${left}::${right}`;
}

/**
 * Canonical text form of ONE IP address: IPv4 dotted quad (IPv4-mapped IPv6 becomes IPv4),
 * IPv6 per RFC 5952 (lowercase, no leading zeros, longest zero run compressed). This matches
 * `CF-Connecting-IP` and the normalised form WAF Lists store. Returns null for CIDRs (`/`) and
 * anything that does not parse, so a range can never slip into a flag or a WAF list item.
 */
export function canonicalIp(value: string): string | null {
	const v = value.trim();
	if (!v || v.includes("/")) return null;
	const bytes = ipToBytes(v);
	return bytes ? bytesToIp(bytes) : null;
}
