import { describe, expect, it } from "vitest";
import type { Fingerprint } from "../src/identity/fingerprint";
import { bytesToIp, importTokenKey, ipToBytes, openToken, sealToken, TOKEN_LENGTH } from "../src/identity/token";

const KEY_A = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_B = "HxwdHh8aGxwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQ=";

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

describe("sealed token", () => {
	it("round-trips an IPv4 fingerprint with a fixed length", async () => {
		const key = await importTokenKey(KEY_A);
		const token = await sealToken(fp(), key);
		expect(token).toHaveLength(TOKEN_LENGTH);
		expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(await openToken(token, [key])).toEqual(fp());
	});

	it("round-trips IPv6 and missing Bot Management", async () => {
		const key = await importTokenKey(KEY_A);
		const v6 = fp({ ip: "2001:db8::1", botScore: null, botManagement: false, jsDetectionPassed: false });
		expect(await openToken(await sealToken(v6, key), [key])).toEqual(v6);
	});

	it("is randomized per request (same fingerprint, different token)", async () => {
		const key = await importTokenKey(KEY_A);
		expect(await sealToken(fp(), key)).not.toEqual(await sealToken(fp(), key));
	});

	it("rejects tampered tokens and wrong keys", async () => {
		const a = await importTokenKey(KEY_A);
		const b = await importTokenKey(KEY_B);
		const token = await sealToken(fp(), a);
		const flipped = token.slice(0, 40) + (token[40] === "A" ? "B" : "A") + token.slice(41);
		expect(await openToken(flipped, [a])).toBeNull();
		expect(await openToken(token, [b])).toBeNull();
		expect(await openToken("not-a-token", [a])).toBeNull();
	});

	it("opens tokens sealed with the previous key during rotation", async () => {
		const current = await importTokenKey(KEY_B);
		const previous = await importTokenKey(KEY_A);
		const old = await sealToken(fp(), previous);
		expect(await openToken(old, [current, previous])).toEqual(fp());
	});

	it("rejects keys that are not 32 bytes", async () => {
		await expect(importTokenKey("c2hvcnQ=")).rejects.toThrow(/32-byte/);
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
