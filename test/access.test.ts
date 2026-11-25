import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { verifyAccessJwt } from "../src/admin/access";
import { handleAdmin } from "../src/admin/router";
import { accessConfig, loadConfig } from "../src/core/config";
import { b64urlEncode } from "../src/core/util";

const TEAM = "team-example.cloudflareaccess.com";
const AUD = "aud-0123456789abcdef";
const ACCESS = accessConfig(TEAM, AUD)!;
const NOW = 1_795_560_000;

let signKey: CryptoKey;
let jwk: JsonWebKey & { kid: string };

const enc = (v: unknown) => b64urlEncode(new TextEncoder().encode(JSON.stringify(v)));

async function jwt(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "k1" }): Promise<string> {
	const input = `${enc(header)}.${enc(claims)}`;
	const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signKey, new TextEncoder().encode(input)));
	return `${input}.${b64urlEncode(sig)}`;
}

const base = { aud: [AUD], iss: `https://${TEAM}`, iat: NOW - 10, nbf: NOW - 10, exp: NOW + 3600 };
const certs = async () => Response.json({ keys: [jwk] });

beforeAll(async () => {
	const pair = (await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	signKey = pair.privateKey;
	jwk = { ...((await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey), kid: "k1" };
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("Access config", () => {
	it("needs both secrets and normalises the team domain", () => {
		expect(accessConfig(TEAM, "")).toBeNull();
		expect(accessConfig("", AUD)).toBeNull();
		expect(accessConfig(`https://${TEAM}/`, AUD)).toEqual({ teamDomain: `https://${TEAM}`, aud: AUD });
	});
});

describe("Access JWT verification", () => {
	it("accepts a user token and returns the email", async () => {
		expect(await verifyAccessJwt(await jwt({ ...base, email: "Owner@Example.com" }), ACCESS, { fetcher: certs, nowSec: NOW })).toEqual({
			kind: "user",
			email: "owner@example.com",
		});
	});

	it("accepts a service-token token (common_name = Client ID)", async () => {
		expect(await verifyAccessJwt(await jwt({ ...base, common_name: "abc123.access" }), ACCESS, { fetcher: certs, nowSec: NOW })).toEqual({
			kind: "service",
			clientId: "abc123.access",
		});
	});

	it.each([
		["another application's audience", { ...base, aud: ["other-aud"], email: "a@example.com" }],
		["another team's issuer", { ...base, iss: "https://evil.cloudflareaccess.com", email: "a@example.com" }],
		["an expired token", { ...base, exp: NOW - 120, email: "a@example.com" }],
		["a token not yet valid", { ...base, nbf: NOW + 600, email: "a@example.com" }],
		["a token without identity", { ...base }],
	])("rejects %s", async (_label, claims) => {
		expect(await verifyAccessJwt(await jwt(claims), ACCESS, { fetcher: certs, nowSec: NOW })).toBeNull();
	});

	it("rejects a tampered payload, alg none, an unknown key and garbage", async () => {
		const good = await jwt({ ...base, email: "a@example.com" });
		const [h, , s] = good.split(".");
		const tampered = `${h}.${enc({ ...base, email: "attacker@example.com" })}.${s}`;
		const none = `${enc({ alg: "none", kid: "k1" })}.${enc({ ...base, email: "a@example.com" })}.`;
		const unknownKid = await jwt({ ...base, email: "a@example.com" }, { alg: "RS256", kid: "rotated-away" });
		for (const t of [tampered, none, unknownKid, "not.a.jwt", ""]) {
			expect(await verifyAccessJwt(t, ACCESS, { fetcher: certs, nowSec: NOW })).toBeNull();
		}
	});

	it("refetches the keys once (uncached) when the kid is unknown, e.g. after rotation", async () => {
		let calls = 0;
		const rotating = async () => (++calls === 1 ? Response.json({ keys: [] }) : Response.json({ keys: [jwk] }));
		expect(await verifyAccessJwt(await jwt({ ...base, email: "a@example.com" }), ACCESS, { fetcher: rotating, nowSec: NOW })).not.toBeNull();
		expect(calls).toBe(2);
	});
});

describe("admin router with Access configured", () => {
	const cfg = loadConfig({ ...env, ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD });
	const whoami = (headers: Record<string, string>) =>
		handleAdmin(new Request("https://honeypot.automatic-demo.com/__hp/whoami", { headers }), env, createExecutionContext(), cfg);

	it("requires the Access JWT: the bearer token alone gets a 404", async () => {
		expect((await whoami({ authorization: "Bearer test-admin-token" })).status).toBe(404);
	});

	it("attributes the request to the Access identity", async () => {
		vi.spyOn(globalThis, "fetch").mockImplementation(certs);
		const real = Math.floor(Date.now() / 1000);
		const token = await jwt({ ...base, iat: real - 5, nbf: real - 5, exp: real + 600, email: "owner@example.com" });
		const res = await whoami({ "cf-access-jwt-assertion": token });
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ auth: "access", actor: { id: "access:owner@example.com", label: "owner@example.com" } });
	});

	it("without Access configured, the bearer token still works (local dev)", async () => {
		const res = await handleAdmin(
			new Request("https://honeypot.automatic-demo.com/__hp/whoami", { headers: { authorization: "Bearer test-admin-token" } }),
			env,
			createExecutionContext(),
			loadConfig(env),
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ auth: "bearer", actor: { id: "admin" } });
	});
});
