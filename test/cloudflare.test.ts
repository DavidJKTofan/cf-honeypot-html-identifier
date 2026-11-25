import { describe, expect, it } from "vitest";
import { buildSubmission, draftAbuseReport } from "../src/integrations/cloudflare/abuse";
import { CLOUDFLARE_IPS_SNAPSHOT, isCloudflareIp, parseCidr } from "../src/integrations/cloudflare/ip-ranges";

const ranges = {
	cidrs: [...CLOUDFLARE_IPS_SNAPSHOT.ipv4_cidrs, ...CLOUDFLARE_IPS_SNAPSHOT.ipv6_cidrs].map((c) => parseCidr(c)!),
	source: "snapshot" as const,
};

describe("Cloudflare IP ranges", () => {
	it.each([
		["104.16.0.10", true],
		["172.67.137.29", true],
		["::ffff:104.21.38.178", true],
		["2606:4700:3035::ac43:891d", true],
		["2a06:98c0:3600::103", true],
		["203.0.113.7", false],
		["8.8.8.8", false],
		["2001:db8::1", false],
		["not-an-ip", false],
	])("%s → %s", (ip, expected) => {
		expect(isCloudflareIp(ip, ranges)).toBe(expected);
	});

	it("parses every snapshot CIDR", () => {
		expect(ranges.cidrs.every(Boolean)).toBe(true);
		expect(parseCidr("10.0.0.0/33")).toBeNull();
	});
});

describe("abuse report draft", () => {
	const draft = draftAbuseReport({
		act: "abuse_dmca",
		caseId: "case-1",
		cloneUrls: ["https://clone.example/a", "https://clone.example/a"],
		originalUrl: "https://honeypot.automatic-demo.com/article",
		sha256: "ab".repeat(32),
		capturedAt: "2026-11-24T00:00:00Z",
		rayIds: ["0123456789abcdef"],
	});

	it("contains no reporter identity and dedupes URLs", () => {
		expect(draft.fields).not.toHaveProperty("email");
		expect(draft.fields.urls).toBe("https://clone.example/a");
		expect(String(draft.fields.comments)).toContain("0123456789abcdef");
	});

	it("never pre-fills the perjury statement (agree / signature) in a draft", () => {
		expect(draft.fields).not.toHaveProperty("agree");
		expect(draft.fields).not.toHaveProperty("signature");
	});

	it("names the scraper's Worker zone and a live reverse proxy in the evidence", () => {
		const live = draftAbuseReport({
			act: "abuse_dmca",
			caseId: "case-2",
			cloneUrls: ["https://clone.example/live/"],
			originalUrl: "https://honeypot.automatic-demo.com/",
			sha256: "cd".repeat(32),
			capturedAt: "2026-11-24T00:00:00Z",
			rayIds: ["0123456789abcdef"],
			workerZones: ["scraper-zone.example", "scraper-zone.example"],
			liveMirror: true,
		});
		const comments = String(live.fields.comments);
		expect(comments).toContain("CF-Worker: scraper-zone.example)");
		expect(comments.match(/scraper-zone\.example/g)).toHaveLength(1);
		expect(comments).toContain("live reverse proxy");
	});

	it("refuses to build a DMCA submission without the required reporter fields", () => {
		expect(buildSubmission(draft, { name: "Jane Doe", email: "jane@example.com" })).toEqual({
			missing: ["address1", "city", "state", "country"],
		});
	});

	it("builds a complete DMCA body with signature = name and email2 = email", () => {
		const built = buildSubmission(draft, {
			name: "Jane Doe",
			email: "jane@example.com",
			company: "Example Trail Co.",
			address1: "1 Example St",
			city: "Example City",
			state: "EX",
			country: "DE",
		});
		expect("body" in built && built.body).toMatchObject({
			act: "abuse_dmca",
			signature: "Jane Doe",
			email2: "jane@example.com",
			agent_name: "Example Trail Co.",
			host_notification: "send",
			owner_notification: "send",
			agree: 1,
		});
	});
});
