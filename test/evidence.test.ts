import { describe, expect, it } from "vitest";
import type { Fingerprint } from "../src/identity/fingerprint";
import { CLOUDFLARE_IPS_SNAPSHOT, parseCidr } from "../src/integrations/cloudflare/ip-ranges";
import { capCaseTokens, decisionTargets, isLiveMirror, needsIngestionWait, secondsBeforeCapture } from "../src/workflows/evidence";
import { attributionRows, escapeMd, shorten } from "../src/workflows/report";
import type { TokenEvidence } from "../src/workflows/types";

const ranges = {
	cidrs: [...CLOUDFLARE_IPS_SNAPSHOT.ipv4_cidrs, ...CLOUDFLARE_IPS_SNAPSHOT.ipv6_cidrs].map((c) => parseCidr(c)!),
	source: "snapshot" as const,
};

const CAPTURED = "2026-11-24T22:46:26.408Z";
const CAPTURED_SEC = Math.floor(Date.parse(CAPTURED) / 1000);

function fp(over: Partial<Fingerprint> = {}): Fingerprint {
	return {
		issuedAt: CAPTURED_SEC - 3600,
		ip: "203.0.113.7",
		asn: 64496,
		country: "DE",
		colo: "DUS",
		botScore: 1,
		verifiedBot: false,
		jsDetectionPassed: false,
		botManagement: true,
		rayId: "0123456789abcdef",
		...over,
	};
}

function ev(over: Partial<Fingerprint> = {}, source: TokenEvidence["source"] = "capture"): TokenEvidence {
	const f = fp(over);
	return {
		carrier: source === "beacon" ? "beacon" : "meta",
		issuedAtIso: new Date(f.issuedAt * 1000).toISOString(),
		fingerprint: f,
		viaCloudflare: false,
		source,
		secondsBeforeCapture: secondsBeforeCapture(f.issuedAt, CAPTURED),
	};
}

describe("live reverse proxy detection", () => {
	it("a token minted during the capture marks a live mirror; an old scrape does not", () => {
		expect(isLiveMirror(ev({ issuedAt: CAPTURED_SEC }))).toBe(true);
		expect(isLiveMirror(ev({ issuedAt: CAPTURED_SEC - 20 }))).toBe(true);
		expect(isLiveMirror(ev({ issuedAt: CAPTURED_SEC - 3600 }))).toBe(false);
	});

	it("a beacon-reported token is never called a live mirror", () => {
		expect(isLiveMirror(ev({ issuedAt: CAPTURED_SEC }, "beacon"))).toBe(false);
	});

	it("waits for Analytics Engine ingestion only when a token is fresh", () => {
		expect(needsIngestionWait([ev({ issuedAt: CAPTURED_SEC - 1 })])).toBe(true);
		expect(needsIngestionWait([ev({ issuedAt: CAPTURED_SEC - 3600 })])).toBe(false);
		expect(needsIngestionWait([])).toBe(false);
	});

	it("an unparseable capture time never triggers a wait", () => {
		expect(secondsBeforeCapture(CAPTURED_SEC, "not a date")).toBe(Number.POSITIVE_INFINITY);
	});
});

describe("decision targets", () => {
	const tokens = [
		ev({ ip: "203.0.113.7" }),
		ev({ ip: "2a06:98c0:3600::103", rayId: "1111111111111111" }),
		ev({ ip: "66.249.66.1", verifiedBot: true, rayId: "2222222222222222" }),
		ev({ ip: "203.0.113.7", rayId: "3333333333333333" }),
	];

	it("skips Cloudflare IPs and verified bots, and dedupes", () => {
		expect(decisionTargets(tokens, undefined, ranges)).toEqual({
			act: ["203.0.113.7"],
			skippedCloudflareIps: ["2a06:98c0:3600::103"],
			skippedVerifiedBotIps: ["66.249.66.1"],
		});
	});

	it("limits to the requested subset and ignores IPs that are not in the case", () => {
		expect(decisionTargets(tokens, ["66.249.66.1", "198.51.100.1"], ranges)).toEqual({
			act: [],
			skippedCloudflareIps: [],
			skippedVerifiedBotIps: ["66.249.66.1"],
		});
	});
});

describe("token cap", () => {
	it("keeps the earliest fetches and the newest few, and counts the rest", () => {
		const tokens = Array.from({ length: 60 }, (_, i) => ev({ issuedAt: CAPTURED_SEC - 10_000 + i, ip: `198.18.0.${i + 1}` }));
		const { kept, omitted } = capCaseTokens([...tokens].reverse(), 50);
		expect(kept).toHaveLength(50);
		expect(omitted).toBe(10);
		const ips = kept.map((t) => t.fingerprint.ip);
		expect(ips.slice(0, 45)).toEqual(tokens.slice(0, 45).map((t) => t.fingerprint.ip)); // earliest first
		expect(ips.slice(45)).toEqual(tokens.slice(55).map((t) => t.fingerprint.ip)); // plus the 5 newest
		expect(capCaseTokens(tokens.slice(0, 3), 50)).toEqual({ kept: tokens.slice(0, 3), omitted: 0 });
	});
});

describe("report rows", () => {
	it("escapes untrusted text so it can't become links, HTML or table cells", () => {
		expect(escapeMd("[click](https://evil.example)")).toBe("\\[click\\]\\(https://evil.example\\)");
		expect(escapeMd("<img src=x onerror=alert(1)>")).toBe("\\<img src=x onerror=alert\\(1\\)\\>");
		expect(escapeMd("a|b\nc")).toBe("a\\|b c");
		expect(escapeMd(null)).toBe("");
	});

	it("shortens long values without cutting a word in half", () => {
		const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
		const out = shorten(ua, 80);
		expect(out.length).toBeLessThanOrEqual(80);
		expect(out.endsWith("…")).toBe(true);
		expect(out).not.toMatch(/like…$/);
		expect(shorten("short", 80)).toBe("short");
	});

	it("carries the evidence source, live-mirror flag and CF-Worker zone", () => {
		const rows = attributionRows({
			decoded: { beaconScript: true, trapLink: true, candidates: 1, tokens: [ev({ issuedAt: CAPTURED_SEC - 2, ip: "2a06:98c0:3600::103" })] },
			enrichment: { "0123456789abcdef": { note: "scraper-zone.example", user_agent: "UA" } as never },
		});
		expect(rows[0]).toMatchObject({ source: "capture", live_mirror: true, seconds_before_capture: 2, cf_worker_zone: "scraper-zone.example" });
	});
});
