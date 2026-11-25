import { describe, expect, it } from "vitest";
import { addTrapDisallow } from "../src/honeypot/trap";

const TRAP = "/catalog/full-export";
const RULE = `Disallow: ${TRAP}`;

/** The rules a crawler with this product token obeys (RFC 9309: its own groups, else `*`). */
function rulesFor(robots: string, token: string): string[] {
	const groups: { agents: string[]; rules: string[] }[] = [];
	let current: { agents: string[]; rules: string[] } | null = null;
	for (const raw of robots.split("\n")) {
		const line = raw.replace(/#.*$/, "").trim();
		if (!line) continue;
		const [key = "", ...rest] = line.split(":");
		const value = rest.join(":").trim();
		if (key.trim().toLowerCase() === "user-agent") {
			if (!current || current.rules.length > 0) groups.push((current = { agents: [], rules: [] }));
			current.agents.push(value.toLowerCase());
		} else if (current) {
			current.rules.push(line);
		}
	}
	const own = groups.filter((g) => g.agents.includes(token.toLowerCase()));
	return (own.length ? own : groups.filter((g) => g.agents.includes("*"))).flatMap((g) => g.rules);
}

describe("robots.txt trap rule", () => {
	it("adds the rule to a plain `*` group without adding another group", () => {
		const out = addTrapDisallow("User-agent: *\nAllow: /\n", TRAP);
		expect(out.match(/User-agent: \*/g)).toHaveLength(1);
		expect(rulesFor(out, "AnyBot")).toContain(RULE);
	});

	it("covers crawlers that have their own group (they ignore `*`)", () => {
		const origin = ["User-agent: Googlebot", "Allow: /", "", "User-agent: *", "Disallow: /private/", "", "Sitemap: https://example.com/sitemap.xml"].join("\n");
		const out = addTrapDisallow(origin, TRAP);
		expect(rulesFor(out, "Googlebot")).toContain(RULE);
		expect(rulesFor(out, "OtherBot")).toEqual(expect.arrayContaining([RULE, "Disallow: /private/"]));
		expect(out).toContain("Sitemap: https://example.com/sitemap.xml");
	});

	it("handles multi-agent groups, comments, CRLF and a trailing user-agent line", () => {
		const origin = "User-agent: A # first\r\nUser-agent: B\r\n# note\r\nCrawl-delay: 10\r\n\r\nUser-agent: C";
		const out = addTrapDisallow(origin, TRAP);
		for (const bot of ["A", "B", "C"]) expect(rulesFor(out, bot)).toContain(RULE);
		expect(out).not.toContain("\r");
		// One rule for the A+B group, one for C, one in the added `*` group.
		expect(out.match(new RegExp(RULE, "g"))).toHaveLength(3);
		expect(rulesFor(out, "Unlisted")).toEqual([RULE]);
	});

	it("adds a `*` group when the file has none, or is empty", () => {
		expect(rulesFor(addTrapDisallow("User-agent: GPTBot\nDisallow: /\n", TRAP), "SomeScraper")).toEqual([RULE]);
		expect(rulesFor(addTrapDisallow("", TRAP), "SomeScraper")).toEqual([RULE]);
	});
});
