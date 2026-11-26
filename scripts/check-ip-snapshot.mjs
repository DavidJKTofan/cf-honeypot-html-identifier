#!/usr/bin/env node
/**
 * Compares CLOUDFLARE_IPS_SNAPSHOT (src/integrations/cloudflare/ip-ranges.ts) with the live
 * list at https://api.cloudflare.com/client/v4/ips (public, no auth). ROADMAP L6.
 *
 * The Worker unions the live list with the snapshot, so a stale snapshot only matters when the
 * live fetch fails: then a range Cloudflare added since the snapshot isn't protected.
 *
 * Prints a GitHub Actions warning when they differ, with a snapshot ready to paste.
 * Exits 0 unless --strict is given (the quarterly CI run uses it, so GitHub sends a notification).
 * A failed fetch is a warning, never an error: the check must not depend on the network.
 */
import { readFile } from "node:fs/promises";

const SOURCE = "src/integrations/cloudflare/ip-ranges.ts";
const API_URL = "https://api.cloudflare.com/client/v4/ips";
const strict = process.argv.includes("--strict");
const gha = process.env.GITHUB_ACTIONS === "true";

const warn = (title, message) => {
	if (gha) console.log(`::warning file=${SOURCE},title=${title}::${message.replaceAll("\n", "%0A")}`);
	else console.warn(`warning: ${title}: ${message}`);
};

async function summary(markdown) {
	if (!process.env.GITHUB_STEP_SUMMARY) return;
	const { appendFile } = await import("node:fs/promises");
	await appendFile(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`);
}

function snapshotFromSource(text) {
	const block = text.match(/CLOUDFLARE_IPS_SNAPSHOT\s*=\s*\{([\s\S]*?)\n\};/)?.[1];
	if (!block) throw new Error(`CLOUDFLARE_IPS_SNAPSHOT not found in ${SOURCE}`);
	const list = (key) => [...(block.match(new RegExp(`${key}:\\s*\\[([\\s\\S]*?)\\]`))?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]);
	const etag = text.match(/Snapshot taken (\S+) \(etag ([0-9a-f]+)\)/);
	return { ipv4: list("ipv4_cidrs"), ipv6: list("ipv6_cidrs"), date: etag?.[1], etag: etag?.[2] };
}

const diff = (a, b) => a.filter((x) => !b.includes(x));

const snap = snapshotFromSource(await readFile(SOURCE, "utf8"));
if (snap.ipv4.length === 0 || snap.ipv6.length === 0) {
	console.error(`${SOURCE}: couldn't read both CIDR lists from CLOUDFLARE_IPS_SNAPSHOT`);
	process.exit(1);
}

let live;
try {
	const res = await fetch(API_URL, { signal: AbortSignal.timeout(15_000), headers: { accept: "application/json" } });
	const body = await res.json();
	if (!res.ok || body.success !== true || !body.result) throw new Error(`HTTP ${res.status}`);
	live = { ipv4: body.result.ipv4_cidrs ?? [], ipv6: body.result.ipv6_cidrs ?? [], etag: body.result.etag };
	if (live.ipv4.length === 0 || live.ipv6.length === 0) throw new Error("empty CIDR list in the answer");
} catch (err) {
	warn("Cloudflare IP snapshot not checked", `Couldn't fetch ${API_URL}: ${err instanceof Error ? err.message : err}`);
	process.exit(0);
}

const added = [...diff(live.ipv4, snap.ipv4), ...diff(live.ipv6, snap.ipv6)];
const removed = [...diff(snap.ipv4, live.ipv4), ...diff(snap.ipv6, live.ipv6)];

if (added.length === 0 && removed.length === 0) {
	const etagNote = live.etag && live.etag !== snap.etag ? ` (etag changed to ${live.etag}; same ranges)` : "";
	console.log(`CLOUDFLARE_IPS_SNAPSHOT matches ${API_URL}: ${snap.ipv4.length} IPv4, ${snap.ipv6.length} IPv6 ranges${etagNote}.`);
	process.exit(0);
}

const today = new Date().toISOString().slice(0, 10);
const quote = (xs) => xs.map((x) => `"${x}"`).join(", ");
const replacement = [
	`/** Snapshot taken ${today} (etag ${live.etag ?? "unknown"}). */`,
	"export const CLOUDFLARE_IPS_SNAPSHOT = {",
	`\tipv4_cidrs: [${quote(live.ipv4)}],`,
	`\tipv6_cidrs: [${quote(live.ipv6)}],`,
	"};",
].join("\n");

const lines = [
	`CLOUDFLARE_IPS_SNAPSHOT (taken ${snap.date ?? "?"}) differs from ${API_URL}.`,
	added.length ? `Added upstream (not protected when the live fetch fails): ${added.join(", ")}` : "",
	removed.length ? `Removed upstream (still protected by the snapshot): ${removed.join(", ")}` : "",
	"Update the snapshot and its etag in ip-ranges.ts.",
].filter(Boolean);

warn("Cloudflare IP snapshot is stale", lines.join("\n"));
console.log(`\nReplacement for ${SOURCE}:\n\n${replacement}\n`);
await summary(`### Cloudflare IP snapshot is stale\n\n${lines.map((l) => `- ${l}`).join("\n")}\n\n\`\`\`ts\n${replacement}\n\`\`\``);
process.exit(strict ? 1 : 0);
