/**
 * Sealed identifier ("the database is the token").
 *
 * A fixed binary fingerprint is encrypted and authenticated with AES-256-GCM (Web Crypto).
 * Only our keys can open it, so a decoded token is proof that we issued that exact string
 * for that exact request, and a tampered or forged token simply fails to open.
 *
 * Both versions seal to 68 bytes, which is 91 base64url characters, so the carriers, the
 * scanner, the beacon's regex and the zero-width carrier are the same for both.
 *
 * Version 2 (sealed with the newest TOKEN_KEYS entry):
 *   0      version (2)    XOR IV[0]   header: readable without a key,
 *   1      key ID (0-255) XOR IV[1]   authenticated as additional data
 *   2..13  IV (12 random bytes)
 *   14..51 ciphertext of the 38-byte payload
 *   52..67 GCM tag (16 bytes)
 * Payload (big-endian):
 *   0..3   issuedAt (uint32 unix seconds)
 *   4..19  client IP (16 bytes, IPv4 stored as IPv4-mapped IPv6)
 *   20..23 ASN (uint32)
 *   24..27 country (2) + colo (3), 6 bits per character (base64url alphabet), 30 bits
 *   28     bot score (0 = Bot Management not present)
 *   29     flags: bit0 verifiedBot, bit1 jsDetection passed, bit2 BM present
 *   30..37 Ray ID (8 bytes from 16 hex chars)
 *
 * Version 1 (sealed with TOKEN_KEY while TOKEN_KEYS is unset; always decodable):
 *   IV(12) || ciphertext(40) || tag(16), no key ID. The 40-byte payload is a version byte (1),
 *   then the v2 fields with country and colo as 5 plain ASCII bytes. Decode tries TOKEN_KEY,
 *   then TOKEN_KEY_PREVIOUS.
 *
 * The header is XORed with the first two IV bytes so that every token still looks uniformly
 * random, like a v1 token or a framework CSRF token: a constant per-key prefix would be a
 * signature to strip by (ROADMAP B2). This is camouflage, not secrecy. Anyone can unmask it,
 * and a token's validity comes only from the key.
 */
import type { Fingerprint } from "./fingerprint";
import { b64Decode, b64urlDecode, b64urlEncode, log } from "../core/util";

export type TokenVersion = 1 | 2;

export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export const V1_PAYLOAD_LENGTH = 40;
export const V2_HEADER_LENGTH = 2;
export const V2_PAYLOAD_LENGTH = 38;
/** Every version seals to this many bytes. */
export const SEALED_LENGTH = IV_LENGTH + V1_PAYLOAD_LENGTH + TAG_LENGTH;
/** Unpadded base64url length of SEALED_LENGTH bytes: 91. */
export const TOKEN_LENGTH = Math.ceil((SEALED_LENGTH * 4) / 3);
export const TOKEN_PATTERN = new RegExp(`^[A-Za-z0-9_-]{${TOKEN_LENGTH}}$`);
/** Key IDs are one byte. */
export const MAX_KEY_ID = 255;

const V1_AAD = new TextEncoder().encode("cf-honeypot-html-identifier/v1");
const V2_AAD_PREFIX = new TextEncoder().encode("cf-honeypot-html-identifier/v2");

/** Additional data for v2: a fixed label plus the unmasked header, so the header can't be altered. */
function v2Aad(keyId: number): Uint8Array {
	const aad = new Uint8Array(V2_AAD_PREFIX.byteLength + V2_HEADER_LENGTH);
	aad.set(V2_AAD_PREFIX, 0);
	aad[V2_AAD_PREFIX.byteLength] = 2;
	aad[V2_AAD_PREFIX.byteLength + 1] = keyId;
	return aad;
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** The secrets and bindings that hold token keys. */
export type TokenKeyEnv = Pick<Env, "TOKEN_KEY" | "TOKEN_KEY_PREVIOUS" | "TOKEN_KEYS" | "TOKEN_KEYS_STORE">;

/** The v1 secrets, in the order decode tries them. */
export type LegacyKeyName = "TOKEN_KEY" | "TOKEN_KEY_PREVIOUS";

function importRawKey(raw: Uint8Array): Promise<CryptoKey> {
	return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function importTokenKey(base64Key: string): Promise<CryptoKey> {
	const raw = b64Decode(base64Key);
	if (!raw || raw.byteLength !== 32) {
		throw new Error("TOKEN_KEY must be a base64-encoded 32-byte key (openssl rand -base64 32)");
	}
	return importRawKey(raw);
}

export interface ParsedKeyRing {
	/** Raw 32-byte keys by ID. */
	keys: Map<number, Uint8Array>;
	/** Entries that were left out, with the reason. Never contains key material. */
	skipped: { keyId: string; reason: string }[];
	/** Set when the whole value is unusable (not JSON, or not an object). */
	error?: string;
}

const KEY_ID = /^(0|[1-9]\d{0,2})$/;

/** A skipped entry's ID, safe to log: an operator who swapped ID and key must not leak the key. */
function loggableKeyId(id: string): string {
	return /^-?\d{1,4}$/.test(id) ? id : "(not a number)";
}

/**
 * Parse TOKEN_KEYS: a JSON object of key ID ("0"-"255") to base64-encoded 32-byte key, for
 * example `{"3":"<base64>","2":"<base64>"}`. Malformed entries are skipped and reported in
 * `skipped`, never fatal; an unparseable value yields an empty ring and `error`.
 */
export function parseTokenKeys(json: string | null | undefined): ParsedKeyRing {
	const keys = new Map<number, Uint8Array>();
	const skipped: ParsedKeyRing["skipped"] = [];
	if (!json || json.trim() === "") return { keys, skipped };
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch {
		return { keys, skipped, error: "not valid JSON" };
	}
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
		return { keys, skipped, error: "expected a JSON object of key ID to base64 key" };
	}
	for (const [id, value] of Object.entries(parsed)) {
		if (!KEY_ID.test(id) || Number(id) > MAX_KEY_ID) {
			skipped.push({ keyId: loggableKeyId(id), reason: `key ID must be an integer from 0 to ${MAX_KEY_ID}` });
			continue;
		}
		const raw = typeof value === "string" ? b64Decode(value) : null;
		if (!raw || raw.byteLength !== 32) {
			skipped.push({ keyId: id, reason: "key must be a base64-encoded 32-byte key (openssl rand -base64 32)" });
			continue;
		}
		keys.set(Number(id), raw);
	}
	return { keys, skipped };
}

/**
 * The ring's JSON: the Secrets Store binding when one is configured, else the TOKEN_KEYS secret.
 * A Secrets Store failure is logged and falls back to TOKEN_KEYS (then TOKEN_KEY), so pages keep
 * getting a valid token.
 */
async function readKeyRingJson(env: TokenKeyEnv): Promise<string | undefined> {
	if (env.TOKEN_KEYS_STORE) {
		try {
			return await env.TOKEN_KEYS_STORE.get();
		} catch (err) {
			log("error", "token keys: TOKEN_KEYS_STORE read failed, using TOKEN_KEYS", {
				event: "token_keys_store_failed",
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return env.TOKEN_KEYS;
}

function newestKeyId(keys: Map<number, Uint8Array>): number | null {
	let newest: number | null = null;
	for (const id of keys.keys()) if (newest === null || id > newest) newest = id;
	return newest;
}

export interface SealingKey {
	key: CryptoKey;
	/** Ring ID (a v2 token), or null for a v1 token sealed with TOKEN_KEY (no usable TOKEN_KEYS). */
	keyId: number | null;
}

/**
 * The key that seals new tokens: the highest TOKEN_KEYS ID, else TOKEN_KEY (version 1).
 * Runs on every HTML response, so it imports one key and logs nothing about the ring;
 * `loadTokenKeys` (beacon, decode, Workflow) reports skipped entries.
 */
export async function loadSealingKey(env: TokenKeyEnv): Promise<SealingKey> {
	const { keys } = parseTokenKeys(await readKeyRingJson(env));
	const id = newestKeyId(keys);
	const raw = id === null ? undefined : keys.get(id);
	if (id === null || !raw) return { key: await importTokenKey(env.TOKEN_KEY), keyId: null };
	return { key: await importRawKey(raw), keyId: id };
}

export interface TokenKeyRing {
	/** The ID that seals new tokens (the highest ring ID), or null while tokens are sealed as v1 with TOKEN_KEY. */
	readonly currentKeyId: number | null;
	/** Ring IDs, newest first. */
	readonly keyIds: readonly number[];
	/** The v2 key with this ID (imported on first use), or null if the ring has none. */
	key(id: number): Promise<CryptoKey | null>;
	/** v1 keys in trial order: TOKEN_KEY, then TOKEN_KEY_PREVIOUS if set and well formed. */
	legacyKeys(): Promise<readonly { name: LegacyKeyName; key: CryptoKey }[]>;
}

/**
 * Build a decode ring. Keys are imported lazily and cached in the ring, which lives for one
 * request or step, so a v2 token costs one import and one decryption whatever the ring's size.
 */
export function createKeyRing(keys: Map<number, Uint8Array>, tokenKey: string, previousKey?: string): TokenKeyRing {
	const ids = [...keys.keys()].sort((a, b) => b - a);
	const imported = new Map<number, Promise<CryptoKey>>();
	let legacy: Promise<{ name: LegacyKeyName; key: CryptoKey }[]> | null = null;
	return {
		currentKeyId: ids[0] ?? null,
		keyIds: ids,
		key(id) {
			const raw = keys.get(id);
			if (!raw) return Promise.resolve(null);
			let key = imported.get(id);
			if (!key) {
				key = importRawKey(raw);
				imported.set(id, key);
			}
			return key;
		},
		legacyKeys() {
			legacy ??= (async () => {
				// TOKEN_KEY is a required secret: a malformed one throws (as before), so a decode
				// fails loudly instead of reporting real tokens as invalid.
				const out: { name: LegacyKeyName; key: CryptoKey }[] = [{ name: "TOKEN_KEY", key: await importTokenKey(tokenKey) }];
				if (previousKey) {
					try {
						out.push({ name: "TOKEN_KEY_PREVIOUS", key: await importTokenKey(previousKey) });
					} catch {
						log("warn", "token keys: TOKEN_KEY_PREVIOUS is malformed and was skipped", { event: "token_keys_entry_skipped" });
					}
				}
				return out;
			})();
			return legacy;
		},
	};
}

/** Every key that may open a token: TOKEN_KEYS (or its Secrets Store binding), TOKEN_KEY, TOKEN_KEY_PREVIOUS. */
export async function loadTokenKeys(env: TokenKeyEnv): Promise<TokenKeyRing> {
	const parsed = parseTokenKeys(await readKeyRingJson(env));
	if (parsed.error) log("error", "token keys: TOKEN_KEYS ignored", { event: "token_keys_invalid", reason: parsed.error });
	for (const s of parsed.skipped) {
		log("warn", "token keys: TOKEN_KEYS entry skipped", { event: "token_keys_entry_skipped", keyId: s.keyId, reason: s.reason });
	}
	return createKeyRing(parsed.keys, env.TOKEN_KEY, env.TOKEN_KEY_PREVIOUS);
}

// ---------------------------------------------------------------------------
// Seal and open
// ---------------------------------------------------------------------------

export async function sealToken(fp: Fingerprint, sealing: SealingKey): Promise<string> {
	return b64urlEncode(sealing.keyId === null ? await sealV1(fp, sealing.key) : await sealV2(fp, sealing.key, sealing.keyId));
}

async function encrypt(key: CryptoKey, iv: Uint8Array, aad: Uint8Array, plain: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plain));
}

async function decrypt(key: CryptoKey, iv: Uint8Array, aad: Uint8Array, data: Uint8Array): Promise<Uint8Array | null> {
	try {
		return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, data));
	} catch {
		return null; // wrong key or tampered token
	}
}

async function sealV1(fp: Fingerprint, key: CryptoKey): Promise<Uint8Array> {
	const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
	const sealed = new Uint8Array(SEALED_LENGTH);
	sealed.set(iv, 0);
	sealed.set(await encrypt(key, iv, V1_AAD, packV1(fp)), IV_LENGTH);
	return sealed;
}

async function sealV2(fp: Fingerprint, key: CryptoKey, keyId: number): Promise<Uint8Array> {
	if (!Number.isInteger(keyId) || keyId < 0 || keyId > MAX_KEY_ID) throw new Error(`token key ID must be an integer from 0 to ${MAX_KEY_ID}`);
	const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
	const sealed = new Uint8Array(SEALED_LENGTH);
	sealed[0] = 2 ^ (iv[0] ?? 0);
	sealed[1] = keyId ^ (iv[1] ?? 0);
	sealed.set(iv, V2_HEADER_LENGTH);
	sealed.set(await encrypt(key, iv, v2Aad(keyId), packV2(fp)), V2_HEADER_LENGTH + IV_LENGTH);
	return sealed;
}

export function tokenToBytes(token: string): Uint8Array | null {
	if (!TOKEN_PATTERN.test(token)) return null;
	const bytes = b64urlDecode(token);
	return bytes && bytes.byteLength === SEALED_LENGTH ? bytes : null;
}

function headerOf(sealed: Uint8Array): { version: 2; keyId: number } | null {
	const version = (sealed[0] ?? 0) ^ (sealed[V2_HEADER_LENGTH] ?? 0);
	const keyId = (sealed[1] ?? 0) ^ (sealed[V2_HEADER_LENGTH + 1] ?? 0);
	return version === 2 ? { version, keyId } : null;
}

/**
 * Read a token's v2 header (its key ID) without a key. Not authenticated: roughly 1 in 256
 * v1 tokens or random strings parse as a v2 header too, and only `openToken` proves anything.
 */
export function readTokenHeader(token: string): { version: 2; keyId: number } | null {
	const sealed = tokenToBytes(token);
	return sealed ? headerOf(sealed) : null;
}

export interface OpenedToken {
	fingerprint: Fingerprint;
	version: TokenVersion;
	/** The ring ID that opened a v2 token; null for v1. */
	keyId: number | null;
	/** The secret that opened a v1 token; null for v2. */
	legacyKey: LegacyKeyName | null;
	/**
	 * Sealed with a key that no longer seals new tokens: a v2 token with an older ring ID, a v1
	 * token once TOKEN_KEYS is in use, or a v1 token that only TOKEN_KEY_PREVIOUS opens.
	 */
	retired: boolean;
}

/**
 * Open a token with the ring. A v2 header picks its key directly (one decryption). Anything
 * else, including the ~1 in 256 v1 tokens whose bytes happen to look like a v2 header, falls
 * back to the v1 keys. Returns null for forged, tampered or unknown-key tokens.
 */
export async function openToken(token: string, ring: TokenKeyRing): Promise<OpenedToken | null> {
	const sealed = tokenToBytes(token);
	if (!sealed) return null;

	const header = headerOf(sealed);
	if (header) {
		const key = await ring.key(header.keyId);
		if (key) {
			const iv = sealed.slice(V2_HEADER_LENGTH, V2_HEADER_LENGTH + IV_LENGTH);
			const plain = await decrypt(key, iv, v2Aad(header.keyId), sealed.slice(V2_HEADER_LENGTH + IV_LENGTH));
			const fingerprint = plain ? unpackV2(plain) : null;
			if (fingerprint) {
				return { fingerprint, version: 2, keyId: header.keyId, legacyKey: null, retired: header.keyId !== ring.currentKeyId };
			}
		}
	}

	const iv = sealed.slice(0, IV_LENGTH);
	const data = sealed.slice(IV_LENGTH);
	for (const { name, key } of await ring.legacyKeys()) {
		const plain = await decrypt(key, iv, V1_AAD, data);
		const fingerprint = plain ? unpackV1(plain) : null;
		if (fingerprint) {
			return { fingerprint, version: 1, keyId: null, legacyKey: name, retired: ring.currentKeyId !== null || name !== "TOKEN_KEY" };
		}
	}
	return null;
}

/**
 * Log one structured warning per retired key among `opened` (event `token_retired_key`), so
 * rotation problems are visible. Old copies carrying an old key are expected; a retired key's
 * token issued AFTER you retired it means something still seals with that key (a stale
 * deployment) or the key leaked. Logs only token fields, never the IP or the reporter's details.
 */
export function logRetiredKeys(source: "beacon" | "decode" | "workflow", opened: readonly OpenedToken[], currentKeyId: number | null): void {
	const groups = new Map<string, { version: TokenVersion; keyId: number | null; legacyKey: LegacyKeyName | null; count: number; oldest: number; newest: number; rayId: string }>();
	for (const t of opened) {
		if (!t.retired) continue;
		const id = `${t.version}:${t.keyId ?? t.legacyKey}`;
		const g = groups.get(id);
		const issuedAt = t.fingerprint.issuedAt;
		if (!g) {
			groups.set(id, { version: t.version, keyId: t.keyId, legacyKey: t.legacyKey, count: 1, oldest: issuedAt, newest: issuedAt, rayId: t.fingerprint.rayId });
			continue;
		}
		g.count++;
		g.oldest = Math.min(g.oldest, issuedAt);
		if (issuedAt > g.newest) {
			g.newest = issuedAt;
			g.rayId = t.fingerprint.rayId;
		}
	}
	for (const g of groups.values()) {
		log("warn", "token sealed with a retired key", {
			event: "token_retired_key",
			source,
			tokenVersion: g.version,
			keyId: g.keyId,
			legacyKey: g.legacyKey,
			currentKeyId,
			count: g.count,
			oldestIssuedAt: new Date(g.oldest * 1000).toISOString(),
			newestIssuedAt: new Date(g.newest * 1000).toISOString(),
			newestRayId: g.rayId,
		});
	}
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

function ascii(value: string, length: number, pad: string): Uint8Array {
	const out = new Uint8Array(length);
	const v = (value + pad.repeat(length)).slice(0, length);
	for (let i = 0; i < length; i++) {
		const code = v.charCodeAt(i);
		out[i] = code >= 0x20 && code < 0x7f ? code : pad.charCodeAt(0);
	}
	return out;
}

/** Country and colo codes are uppercase letters (plus "T1", "XX", "-" padding): all in this 64-symbol alphabet. */
const GEO_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function geoChars(value: string, length: number, pad: string): string {
	const v = value + pad.repeat(length);
	let out = "";
	for (let i = 0; i < length; i++) {
		const c = v.charAt(i);
		out += GEO_ALPHABET.indexOf(c) >= 0 ? c : pad; // charAt is one UTF-16 unit, so never ""
	}
	return out;
}

/** Country (2) and colo (3) as five 6-bit symbols: 30 bits, top 2 bits zero. */
function packGeo(country: string, colo: string): number {
	let value = 0;
	for (const c of geoChars(country, 2, "X") + geoChars(colo, 3, "-")) value = value * 64 + GEO_ALPHABET.indexOf(c);
	return value;
}

function unpackGeo(value: number): { country: string; colo: string } | null {
	if (value >= 2 ** 30) return null;
	let chars = "";
	for (let i = 0; i < 5; i++) {
		chars = GEO_ALPHABET.charAt(value % 64) + chars;
		value = Math.floor(value / 64);
	}
	return { country: chars.slice(0, 2), colo: chars.slice(2) };
}

function rayBytes(rayId: string): Uint8Array {
	const ray = /^[0-9a-f]{16}$/i.test(rayId) ? rayId : "0".repeat(16);
	const out = new Uint8Array(8);
	for (let i = 0; i < 8; i++) out[i] = Number.parseInt(ray.slice(i * 2, i * 2 + 2), 16);
	return out;
}

function rayHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function flagsOf(fp: Fingerprint): number {
	return (fp.verifiedBot ? 1 : 0) | (fp.jsDetectionPassed ? 2 : 0) | (fp.botManagement ? 4 : 0);
}

function botFields(score: number, flags: number): Pick<Fingerprint, "botScore" | "verifiedBot" | "jsDetectionPassed" | "botManagement"> {
	return {
		botScore: score === 0 ? null : score,
		verifiedBot: (flags & 1) !== 0,
		jsDetectionPassed: (flags & 2) !== 0,
		botManagement: (flags & 4) !== 0,
	};
}

function packV1(fp: Fingerprint): Uint8Array {
	const buf = new Uint8Array(V1_PAYLOAD_LENGTH);
	const view = new DataView(buf.buffer);
	view.setUint8(0, 1);
	view.setUint32(1, fp.issuedAt >>> 0);
	buf.set(ipToBytes(fp.ip) ?? new Uint8Array(16), 5);
	view.setUint32(21, fp.asn >>> 0);
	buf.set(ascii(fp.country, 2, "X"), 25);
	buf.set(ascii(fp.colo, 3, "-"), 27);
	view.setUint8(30, fp.botScore ?? 0);
	view.setUint8(31, flagsOf(fp));
	buf.set(rayBytes(fp.rayId), 32);
	return buf;
}

function unpackV1(buf: Uint8Array): Fingerprint | null {
	if (buf.byteLength !== V1_PAYLOAD_LENGTH) return null;
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	if (view.getUint8(0) !== 1) return null;
	const text = (from: number, to: number) => String.fromCharCode(...buf.slice(from, to));
	return {
		issuedAt: view.getUint32(1),
		ip: bytesToIp(buf.slice(5, 21)),
		asn: view.getUint32(21),
		country: text(25, 27),
		colo: text(27, 30),
		...botFields(view.getUint8(30), view.getUint8(31)),
		rayId: rayHex(buf.slice(32, 40)),
	};
}

function packV2(fp: Fingerprint): Uint8Array {
	const buf = new Uint8Array(V2_PAYLOAD_LENGTH);
	const view = new DataView(buf.buffer);
	view.setUint32(0, fp.issuedAt >>> 0);
	buf.set(ipToBytes(fp.ip) ?? new Uint8Array(16), 4);
	view.setUint32(20, fp.asn >>> 0);
	view.setUint32(24, packGeo(fp.country, fp.colo));
	view.setUint8(28, fp.botScore ?? 0);
	view.setUint8(29, flagsOf(fp));
	buf.set(rayBytes(fp.rayId), 30);
	return buf;
}

function unpackV2(buf: Uint8Array): Fingerprint | null {
	if (buf.byteLength !== V2_PAYLOAD_LENGTH) return null;
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const geo = unpackGeo(view.getUint32(24));
	if (!geo) return null;
	return {
		issuedAt: view.getUint32(0),
		ip: bytesToIp(buf.slice(4, 20)),
		asn: view.getUint32(20),
		country: geo.country,
		colo: geo.colo,
		...botFields(view.getUint8(28), view.getUint8(29)),
		rayId: rayHex(buf.slice(30, 38)),
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
