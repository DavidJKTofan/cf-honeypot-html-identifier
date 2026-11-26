#!/usr/bin/env node
/**
 * Deploy drift check (`npm run doctor`, ROADMAP T1). Run it before a live test.
 *
 * Fails when:
 *   1. the code deployed to production is older than the last commit on `main` that changes
 *      what gets deployed (src/, public/, migrations/, wrangler.jsonc, package*.json), or
 *      production was rolled back; or
 *   2. the remote D1 database has migrations that haven't been applied.
 *
 * Read-only apart from `wrangler d1 migrations list`, which creates the d1_migrations table if
 * it doesn't exist. Uses the top-level (production) config and your Wrangler login or
 * CLOUDFLARE_API_TOKEN; set CLOUDFLARE_ACCOUNT_ID in .env if you have more than one account.
 *
 * Exit codes: 0 in sync, 1 drift found, 2 a check couldn't run.
 */
import { spawnSync } from "node:child_process";

const DEPLOYED_PATHS = ["src", "public", "migrations", "wrangler.jsonc", "package.json", "package-lock.json"];
const WIN = process.platform === "win32";

function run(cmd, args, { timeout = 120_000 } = {}) {
	const r = spawnSync(cmd, args, { encoding: "utf8", timeout, shell: WIN, env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" } });
	return { ok: r.status === 0, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error };
}

const wrangler = (args) => run("npx", ["--no-install", "wrangler", ...args]);
const git = (args, opts) => run("git", args, opts);
const tail = (text, n = 12) => text.trim().split("\n").slice(-n).map((l) => `    ${l}`).join("\n");

let drift = false;
let broken = false;
const fail = (msg) => {
	drift = true;
	console.log(`✘ ${msg}`);
};
const cannot = (msg, detail = "") => {
	broken = true;
	console.log(`? ${msg}${detail ? `\n${tail(detail)}` : ""}`);
};

// --- 1. Deployed code vs main -------------------------------------------------------------

function mainCommit() {
	const fetched = git(["fetch", "--quiet", "origin", "main"], { timeout: 20_000 });
	const hasOrigin = git(["rev-parse", "--verify", "--quiet", "origin/main"]).ok;
	const ref = hasOrigin ? "origin/main" : "main";
	if (!fetched.ok) console.log(`! couldn't fetch origin/main; comparing with the local ${ref}`);
	// --first-parent: a merged PR counts at its merge time, not at its branch commits' times.
	const log = git(["log", "-1", "--first-parent", "--format=%h%x09%cI%x09%s", ref, "--", ...DEPLOYED_PATHS]);
	const [sha, iso, ...subject] = log.stdout.trim().split("\t");
	if (!log.ok || !sha || !iso) return { ref, error: log.stderr || "no commit found" };
	return { ref, sha, time: new Date(iso), subject: subject.join("\t") };
}

function checkDeployment() {
	const main = mainCommit();
	if (main.error) return cannot(`couldn't read the last deployable commit on ${main.ref}`, main.error);

	const res = wrangler(["deployments", "list", "--json", "--env="]);
	if (!res.ok) return cannot("`wrangler deployments list --json` failed (logged in? CLOUDFLARE_ACCOUNT_ID set?)", res.stderr || res.stdout);
	let deployments;
	try {
		deployments = JSON.parse(res.stdout.slice(res.stdout.indexOf("[")));
	} catch {
		return cannot("couldn't parse `wrangler deployments list --json`", res.stdout);
	}
	if (!Array.isArray(deployments) || deployments.length === 0) return fail("the Worker has no deployments");

	// Newest first. A secret change re-deploys the current code, so it says nothing about its age.
	const newestFirst = [...deployments].sort((a, b) => String(b.created_on).localeCompare(String(a.created_on)));
	const trigger = (d) => d.annotations?.["workers/triggered_by"];
	const code = newestFirst.find((d) => trigger(d) !== "secret");
	if (!code) return cannot("the 10 latest deployments are all secret changes; check `npx wrangler versions list`");

	const deployedAt = new Date(code.created_on);
	const when = deployedAt.toISOString();
	if (trigger(code) === "rollback") return fail(`production was rolled back at ${when}: run \`npm run deploy\` from ${main.ref}`);
	if (deployedAt < main.time) {
		return fail(
			`deployed ${when}, before ${main.ref} ${main.sha} (${main.time.toISOString()}, "${main.subject}"): run \`npm run deploy\``,
		);
	}
	console.log(`✔ deployed ${when}, after ${main.ref} ${main.sha} (${main.time.toISOString()})`);
}

// --- 2. Pending remote migrations ---------------------------------------------------------

function checkMigrations() {
	const res = wrangler(["d1", "migrations", "list", "DB", "--remote", "--env="]);
	const out = `${res.stdout}\n${res.stderr}`;
	if (!res.ok) return cannot("`wrangler d1 migrations list DB --remote` failed", out);
	if (out.includes("No migrations to apply")) return console.log("✔ remote D1 has every migration applied");
	if (out.includes("Migrations to be applied")) {
		const pending = [...new Set(out.match(/[\w.-]+\.sql/g) ?? [])];
		fail(`remote D1 has unapplied migrations: ${pending.join(", ") || "(names not parsed)"}; run \`npm run db:migrate:remote\``);
		if (pending.length === 0) console.log(tail(out));
		return;
	}
	cannot("unrecognized `wrangler d1 migrations list` output", out);
}

checkDeployment();
checkMigrations();

if (drift) process.exit(1);
if (broken) process.exit(2);
console.log("No drift: production matches main.");
