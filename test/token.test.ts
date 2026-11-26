import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeTokens } from "../src/admin/decode";
import { loadConfig } from "../src/core/config";
import { b64urlEncode } from "../src/core/util";
import { beaconScript } from "../src/honeypot/beacon";
import type { Fingerprint } from "../src/identity/fingerprint";
import {
	bytesToIp,
	importTokenKey,
	IV_LENGTH,
	ipToBytes,
	loadSealingKey,
	loadTokenKeys,
	logRetiredKeys,
	openToken,
	parseTokenKeys,
	readTokenHeader,
	SEALED_LENGTH,
	sealToken,
	TAG_LENGTH,
	TOKEN_LENGTH,
	TOKEN_PATTERN,
	tokenToBytes,
	V1_PAYLOAD_LENGTH,
	V2_HEADER_LENGTH,
	V2_PAYLOAD_LENGTH,
	type OpenedToken,
	type TokenKeyEnv,
} from "../src/identity/token";
import { ZW_LENGTH } from "../src/identity/zerowidth";

const KEY_A = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_B = "HxwdHh8aGxwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQ=";
const KEY_C = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";

function fp(overrides: Partial<Fingerprint> = {}): Fingerprint {
	return {
		issuedAt: 1_764_000_000,
		ip: "203.0.113.42",
		asn: 64496,
		country: "DE",
		colo: "FRA",
		botScore: 12,
		verifiedBot: false,
		jsDetectionPassed: true,
		botManagement: true,
		rayId: "8c1a2b3c4d5e6f70",
		...overrides,
	};
}

/** Token key secrets: TOKEN_KEY = KEY_A unless overridden; `ring` becomes TOKEN_KEYS. */
function keyEnv(ring?: Record<string, unknown>, extra: Partial<TokenKeyEnv> = {}): TokenKeyEnv {
	return { TOKEN_KEY: KEY_A, ...(ring ? { TOKEN_KEYS: JSON.stringify(ring) } : {}), ...extra };
}

async function seal(e: TokenKeyEnv, f: Fingerprint = fp()): Promise<string> {
	return sealToken(f, await loadSealingKey(e));
}

async function open(token: string, e: TokenKeyEnv): Promise<OpenedToken | null> {
	return openToken(token, await loadTokenKeys(e));
}

/** Re-encode a token after changing its bytes. */
function mutate(token: string, change: (bytes: Uint8Array) => void): string {
	const bytes = tokenToBytes(token) as Uint8Array;
	change(bytes);
	return b64urlEncode(bytes);
}

/** Parsed JSON log lines written to a console method. */
function logged(spy: { mock: { calls: unknown[][] } }): Record<string, unknown>[] {
	return spy.mock.calls.flatMap((c) => {
		try {
			return [JSON.parse(String(c[0])) as Record<string, unknown>];
		} catch {
			return [];
		}
	});
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("version 2 tokens (TOKEN_KEYS)", () => {
	it("round-trips an IPv4 fingerprint, with the key ID readable without the key", async () => {
		const e = keyEnv({ "7": KEY_B });
		const sealing = await loadSealingKey(e);
		expect(sealing.keyId).toBe(7);
		const token = await sealToken(fp(), sealing);
		expect(token).toHaveLength(TOKEN_LENGTH);
		expect(token).toMatch(TOKEN_PATTERN);
		expect(readTokenHeader(token)).toEqual({ version: 2, keyId: 7 });
		expect(await open(token, e)).toEqual({ fingerprint: fp(), version: 2, keyId: 7, legacyKey: null, retired: false });
	});

	it("round-trips IPv6, missing Bot Management and extreme field values", async () => {
		const e = keyEnv({ "0": KEY_B });
		const cases = [
			fp({ ip: "2001:db8::1", botScore: null, botManagement: false, jsDetectionPassed: false, country: "T1", colo: "---" }),
			fp({ ip: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", issuedAt: 2 ** 32 - 1, asn: 2 ** 32 - 1, botScore: 99, verifiedBot: true, rayId: "ffffffffffffffff", country: "XX", colo: "ZZZ" }),
			fp({ ip: "::", issuedAt: 0, asn: 0, botScore: 1, rayId: "0000000000000000", country: "AA", colo: "AAA" }),
		];
		for (const f of cases) expect((await open(await seal(e, f), e))?.fingerprint).toEqual(f);
	});

	it("pads short geo codes and replaces characters outside the alphabet, like version 1", async () => {
		const e = keyEnv({ "1": KEY_B });
		const opened = await open(await seal(e, fp({ country: "ü", colo: "AB" })), e);
		expect(opened?.fingerprint).toMatchObject({ country: "XX", colo: "AB-" });
	});

	it("is randomized per request and its header is masked, so tokens share no constant prefix", async () => {
		const e = keyEnv({ "3": KEY_B });
		const tokens = await Promise.all(Array.from({ length: 32 }, () => seal(e)));
		expect(new Set(tokens).size).toBe(32);
		expect(new Set(tokens.map((t) => t.slice(0, 3))).size).toBeGreaterThan(1);
		for (const t of tokens) expect(readTokenHeader(t)).toEqual({ version: 2, keyId: 3 });
	});

	it("rotates across three keys: the newest ID seals, every ID in the ring decodes", async () => {
		const t1 = await seal(keyEnv({ "1": KEY_A }));
		const t2 = await seal(keyEnv({ "2": KEY_B, "1": KEY_A }));
		// Entry order doesn't matter: the highest ID seals.
		const ring3 = keyEnv({ "1": KEY_A, "3": KEY_C, "2": KEY_B });
		const t3 = await seal(ring3);
		expect([t1, t2, t3].map((t) => readTokenHeader(t)?.keyId)).toEqual([1, 2, 3]);

		const ring = await loadTokenKeys(ring3);
		expect(ring.currentKeyId).toBe(3);
		expect(ring.keyIds).toEqual([3, 2, 1]);
		const opened = await Promise.all([t1, t2, t3].map((t) => openToken(t, ring)));
		expect(opened.map((o) => [o?.keyId, o?.retired])).toEqual([
			[1, true],
			[2, true],
			[3, false],
		]);
		for (const o of opened) expect(o?.fingerprint).toEqual(fp());

		// Key 1 dropped from the ring: its copies no longer decode, the others still do.
		const dropped = keyEnv({ "3": KEY_C, "2": KEY_B });
		expect(await open(t1, dropped)).toBeNull();
		expect((await open(t2, dropped))?.keyId).toBe(2);
		expect((await open(t3, dropped))?.keyId).toBe(3);
	});

	it("rejects unknown key IDs, and an ID reused for a different key", async () => {
		const token = await seal(keyEnv({ "9": KEY_B }));
		expect(await open(token, keyEnv({ "8": KEY_B }))).toBeNull();
		expect(await open(token, keyEnv())).toBeNull(); // no ring: only v1 keys
		expect(await open(token, keyEnv({ "9": KEY_C }))).toBeNull();
		expect(await open(token, keyEnv(undefined, { TOKEN_KEY: KEY_B }))).toBeNull(); // the v1 path never opens v2 bytes
	});

	it("rejects tampering with the header, IV, ciphertext or tag", async () => {
		const e = keyEnv({ "1": KEY_A, "2": KEY_B });
		const token = await seal(e);
		expect(await open(token, e)).not.toBeNull();
		const at = {
			version: 0,
			keyId: 1,
			iv: V2_HEADER_LENGTH + 5,
			ciphertext: V2_HEADER_LENGTH + IV_LENGTH + 10,
			tag: SEALED_LENGTH - 1,
		};
		for (const [part, i] of Object.entries(at)) {
			const tampered = mutate(token, (b) => {
				b[i] = (b[i] ?? 0) ^ 0x01;
			});
			expect(await open(tampered, e), part).toBeNull();
		}
		// Relabel the header to the other key ID in the ring (still masked correctly): the AAD differs.
		const relabeled = mutate(token, (b) => {
			b[1] = (b[1] ?? 0) ^ 2 ^ 1;
		});
		expect(readTokenHeader(relabeled)).toEqual({ version: 2, keyId: 1 });
		expect(await open(relabeled, e)).toBeNull();
		expect(await open("not-a-token", e)).toBeNull();
	});

	it("still opens a version 1 token whose random bytes look like a version 2 header", async () => {
		const v1 = await loadSealingKey(keyEnv());
		let token = "";
		for (let i = 0; i < 20_000 && !readTokenHeader(token); i++) token = await sealToken(fp(), v1);
		const header = readTokenHeader(token);
		expect(header).not.toBeNull();
		// The ring even has a key under that ID: the v2 attempt fails, then the v1 fallback opens it.
		const e = keyEnv({ [String(header?.keyId)]: KEY_B });
		expect(await open(token, e)).toMatchObject({ fingerprint: fp(), version: 1, legacyKey: "TOKEN_KEY" });
	});
});

describe("version 1 tokens (TOKEN_KEY, TOKEN_KEY_PREVIOUS)", () => {
	it("are sealed while TOKEN_KEYS is unset, and are not retired", async () => {
		const e = keyEnv();
		const sealing = await loadSealingKey(e);
		expect(sealing.keyId).toBeNull();
		const token = await sealToken(fp(), sealing);
		expect(token).toHaveLength(TOKEN_LENGTH);
		expect(await open(token, e)).toEqual({ fingerprint: fp(), version: 1, keyId: null, legacyKey: "TOKEN_KEY", retired: false });
		const v6 = fp({ ip: "2001:db8::1", botScore: null, botManagement: false, jsDetectionPassed: false });
		expect((await open(await seal(e, v6), e))?.fingerprint).toEqual(v6);
	});

	it("open with TOKEN_KEY_PREVIOUS after a v1 rotation, flagged as retired", async () => {
		const old = await seal(keyEnv());
		const rotated = keyEnv(undefined, { TOKEN_KEY: KEY_B, TOKEN_KEY_PREVIOUS: KEY_A });
		expect(await open(old, rotated)).toMatchObject({ fingerprint: fp(), version: 1, legacyKey: "TOKEN_KEY_PREVIOUS", retired: true });
	});

	it("keep opening once a ring seals, with TOKEN_KEY and TOKEN_KEY_PREVIOUS", async () => {
		const byKey = await seal(keyEnv());
		const byPrevious = await seal(keyEnv(undefined, { TOKEN_KEY: KEY_B }));
		const e = keyEnv({ "1": KEY_C }, { TOKEN_KEY_PREVIOUS: KEY_B });
		expect(await open(byKey, e)).toMatchObject({ version: 1, legacyKey: "TOKEN_KEY", retired: true });
		expect(await open(byPrevious, e)).toMatchObject({ version: 1, legacyKey: "TOKEN_KEY_PREVIOUS", retired: true });
	});

	it("rejects tampered tokens and wrong keys", async () => {
		const token = await seal(keyEnv());
		const flipped = token.slice(0, 40) + (token[40] === "A" ? "B" : "A") + token.slice(41);
		expect(await open(flipped, keyEnv())).toBeNull();
		expect(await open(token, keyEnv(undefined, { TOKEN_KEY: KEY_B }))).toBeNull();
		expect(await open(token, keyEnv({ "1": KEY_A }, { TOKEN_KEY: KEY_B }))).toBeNull(); // ring keys never open v1 tokens
	});

	it("skips a malformed TOKEN_KEY_PREVIOUS instead of failing", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const token = await seal(keyEnv());
		expect((await open(token, keyEnv(undefined, { TOKEN_KEY_PREVIOUS: "c2hvcnQ=" })))?.legacyKey).toBe("TOKEN_KEY");
		expect(logged(warn).map((l) => l.event)).toContain("token_keys_entry_skipped");
	});

	it("rejects keys that are not 32 bytes", async () => {
		await expect(importTokenKey("c2hvcnQ=")).rejects.toThrow(/32-byte/);
	});
});

describe("TOKEN_KEYS parsing", () => {
	it("skips and logs malformed entries without key material, and never fails", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const ring = {
			"3": KEY_C,
			"01": KEY_B,
			"256": KEY_B,
			"-1": KEY_B,
			x: KEY_B,
			"4": "c2hvcnQ=",
			"5": 42,
			"6": null,
			[KEY_A]: "7", // ID and key swapped: the key must not reach the logs
		};
		const parsed = parseTokenKeys(JSON.stringify(ring));
		expect([...parsed.keys.keys()]).toEqual([3]);
		expect(parsed.skipped.map((s) => s.keyId).sort()).toEqual(["(not a number)", "(not a number)", "-1", "01", "256", "4", "5", "6"].sort());
		expect(parsed.error).toBeUndefined();

		expect((await loadSealingKey(keyEnv(ring))).keyId).toBe(3);
		const loaded = await loadTokenKeys(keyEnv(ring));
		expect(loaded.keyIds).toEqual([3]);
		const lines = logged(warn);
		expect(lines.filter((l) => l.event === "token_keys_entry_skipped")).toHaveLength(8);
		const text = warn.mock.calls.map((c) => String(c[0])).join("\n");
		for (const key of [KEY_A, KEY_B, KEY_A.slice(0, 12)]) expect(text).not.toContain(key);
	});

	it("falls back to TOKEN_KEY (version 1) when TOKEN_KEYS is unset, empty, unparseable or has no usable entry", async () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		vi.spyOn(console, "warn").mockImplementation(() => {});
		for (const value of [undefined, "", "  ", "{not json", "[1,2]", "null", '"text"', JSON.stringify({ "1": "short" }), "{}"]) {
			const e: TokenKeyEnv = { TOKEN_KEY: KEY_A, ...(value === undefined ? {} : { TOKEN_KEYS: value }) };
			expect((await loadSealingKey(e)).keyId, String(value)).toBeNull();
			const ring = await loadTokenKeys(e);
			expect(ring.currentKeyId).toBeNull();
			expect((await openToken(await seal(e), ring))?.version).toBe(1);
		}
		expect(logged(error).filter((l) => l.event === "token_keys_invalid").length).toBeGreaterThanOrEqual(4);
	});
});

describe("Secrets Store binding (TOKEN_KEYS_STORE)", () => {
	it("is used instead of TOKEN_KEYS", async () => {
		const store = { get: async () => JSON.stringify({ "5": KEY_C }) } as SecretsStoreSecret;
		const e = keyEnv({ "4": KEY_B }, { TOKEN_KEYS_STORE: store });
		const token = await seal(e);
		expect(readTokenHeader(token)?.keyId).toBe(5);
		expect((await open(token, e))?.keyId).toBe(5);
	});

	it("falls back to TOKEN_KEYS, and logs, when the store can't be read", async () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		const store = {
			get: async () => {
				throw new Error("store unavailable");
			},
		} as SecretsStoreSecret;
		const e = keyEnv({ "4": KEY_B }, { TOKEN_KEYS_STORE: store });
		expect((await loadSealingKey(e)).keyId).toBe(4);
		expect(logged(error).map((l) => l.event)).toContain("token_keys_store_failed");
	});
});

describe("retired key warnings", () => {
	it("logs one warning per retired key with token fields only", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const e = keyEnv({ "2": KEY_B, "1": KEY_A });
		const old = { "1": KEY_A };
		const tokens = [
			await seal(keyEnv(old), fp({ issuedAt: 1_700_000_000, rayId: "1111111111111111" })),
			await seal(keyEnv(old), fp({ issuedAt: 1_700_086_400, rayId: "2222222222222222" })),
			await seal(e),
		];
		const ring = await loadTokenKeys(e);
		const opened = (await Promise.all(tokens.map((t) => openToken(t, ring)))).filter((o): o is OpenedToken => o !== null);
		logRetiredKeys("decode", opened, ring.currentKeyId);
		const lines = logged(warn).filter((l) => l.event === "token_retired_key");
		expect(lines).toEqual([
			{
				level: "warn",
				message: "token sealed with a retired key",
				event: "token_retired_key",
				source: "decode",
				tokenVersion: 2,
				keyId: 1,
				legacyKey: null,
				currentKeyId: 2,
				count: 2,
				oldestIssuedAt: "2023-11-14T22:13:20.000Z",
				newestIssuedAt: "2023-11-15T22:13:20.000Z",
				newestRayId: "2222222222222222",
			},
		]);
		expect(JSON.stringify(lines)).not.toContain(fp().ip);
	});

	it("decodeTokens reports the key ID and warns from the Workflow path", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		// The test ring in vitest.config.ts: ID 2 seals, ID 1 is retired.
		const current = await sealToken(fp(), await loadSealingKey(env));
		const retired = await sealToken(fp(), { key: await importTokenKey("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="), keyId: 1 });
		const results = await decodeTokens(
			env,
			[
				{ carrier: "meta", token: current },
				{ carrier: "attr:a[href]", token: retired },
				{ carrier: "meta-fallback", token: "x".repeat(TOKEN_LENGTH) },
			],
			{ enrich: false, source: "workflow" },
		);
		expect(results.map((r) => [r.valid, r.version, r.keyId, r.retiredKey])).toEqual([
			[true, 2, 2, false],
			[true, 2, 1, true],
			[false, null, null, false],
		]);
		expect(logged(warn).filter((l) => l.event === "token_retired_key")).toMatchObject([{ source: "workflow", keyId: 1, currentKeyId: 2, count: 1 }]);
	});
});

describe("length invariant", () => {
	it("keeps every version at 68 sealed bytes and 91 base64url characters", async () => {
		expect(SEALED_LENGTH).toBe(68);
		expect(IV_LENGTH + V1_PAYLOAD_LENGTH + TAG_LENGTH).toBe(SEALED_LENGTH);
		expect(V2_HEADER_LENGTH + IV_LENGTH + V2_PAYLOAD_LENGTH + TAG_LENGTH).toBe(SEALED_LENGTH);
		expect(TOKEN_LENGTH).toBe(91);
		expect(TOKEN_PATTERN.source).toBe("^[A-Za-z0-9_-]{91}$");
		expect(ZW_LENGTH).toBe(SEALED_LENGTH * 4);
		expect(beaconScript("https://honeypot.example", loadConfig(env))).toContain("/^[A-Za-z0-9_-]{91}$/");
		for (const e of [keyEnv(), keyEnv({ "255": KEY_B })]) {
			for (const f of [fp(), fp({ ip: "2001:db8::1" })]) {
				const token = await seal(e, f);
				expect(token).toMatch(TOKEN_PATTERN);
				expect(tokenToBytes(token)?.byteLength).toBe(SEALED_LENGTH);
			}
		}
	});
});

describe("IP packing", () => {
	it.each([
		["203.0.113.42", "203.0.113.42"],
		["::ffff:198.51.100.7", "198.51.100.7"],
		["2001:db8::1", "2001:db8::1"],
		["2001:0db8:0000:0000:0000:ff00:0042:8329", "2001:db8::ff00:42:8329"],
		["::1", "::1"],
		["::", "::"],
		["fe80::1%eth0", "fe80::1"],
		["2001:db8:0:1:0:0:0:1", "2001:db8:0:1::1"],
	])("%s → %s", (input, expected) => {
		const bytes = ipToBytes(input);
		expect(bytes).not.toBeNull();
		expect(bytesToIp(bytes as Uint8Array)).toBe(expected);
	});

	it("rejects garbage", () => {
		expect(ipToBytes("999.1.1.1")).toBeNull();
		expect(ipToBytes("1:2:3")).toBeNull();
		expect(ipToBytes("hello")).toBeNull();
	});
});
