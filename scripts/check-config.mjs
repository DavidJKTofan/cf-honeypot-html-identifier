#!/usr/bin/env node
/**
 * Config guard for wrangler.jsonc (part of `npm run lint`, ROADMAP L10).
 *
 * - Production (the top level) must not list a local host in CANONICAL_HOSTS: the beacon
 *   script embeds that list in every page.
 * - Wrangler environments don't inherit vars, secrets or bindings, so `env.dev` repeats them.
 *   It may differ from the top level only in its name, its routes (none) and CANONICAL_HOSTS
 *   (the production hosts plus local ones). Anything else that differs is drift.
 *
 * Reads the config with Wrangler's own parser. No network, no account needed.
 */
import { isDeepStrictEqual } from "node:util";
import { unstable_readConfig } from "wrangler";

const CONFIG = "wrangler.jsonc";
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const ALLOWED_DIFFS = new Set(["targetEnvironment", "name", "routes", "vars"]);

const read = (env) => unstable_readConfig({ config: CONFIG, env }, { hideWarnings: true });
const hosts = (value) =>
	String(value ?? "")
		.split(",")
		.map((h) => h.trim().toLowerCase())
		.filter(Boolean);

const top = read(undefined);
const dev = read("dev");
const errors = [];

const prodHosts = hosts(top.vars?.CANONICAL_HOSTS);
const localInProd = prodHosts.filter((h) => LOCAL_HOSTS.has(h));
if (prodHosts.length === 0) errors.push("top-level vars.CANONICAL_HOSTS is empty");
if (localInProd.length > 0) {
	errors.push(`top-level vars.CANONICAL_HOSTS lists ${localInProd.join(", ")}: local hosts belong in env.dev only`);
}

if (dev.targetEnvironment !== "dev") errors.push("env.dev is missing");
if (!Array.isArray(dev.routes) || dev.routes.length > 0) {
	errors.push("env.dev must set \"routes\": [] so it can never take the production hostname");
}

for (const key of Object.keys({ ...top, ...dev })) {
	if (ALLOWED_DIFFS.has(key)) continue;
	if (!isDeepStrictEqual(top[key], dev[key])) errors.push(`env.dev.${key} differs from the top level`);
}

const varNames = new Set([...Object.keys(top.vars ?? {}), ...Object.keys(dev.vars ?? {})]);
for (const name of varNames) {
	if (name === "CANONICAL_HOSTS") continue;
	if (!isDeepStrictEqual(top.vars?.[name], dev.vars?.[name])) errors.push(`env.dev.vars.${name} differs from the top level`);
}

const devHosts = hosts(dev.vars?.CANONICAL_HOSTS);
const missing = prodHosts.filter((h) => !devHosts.includes(h));
const extra = devHosts.filter((h) => !prodHosts.includes(h) && !LOCAL_HOSTS.has(h));
if (missing.length > 0) errors.push(`env.dev.vars.CANONICAL_HOSTS is missing ${missing.join(", ")}`);
if (extra.length > 0) errors.push(`env.dev.vars.CANONICAL_HOSTS adds non-local hosts: ${extra.join(", ")}`);

if (errors.length > 0) {
	console.error(`${CONFIG}:`);
	for (const e of errors) console.error(`  - ${e}`);
	process.exit(1);
}
console.log(`${CONFIG}: production has no local hosts; env.dev matches the top level.`);
