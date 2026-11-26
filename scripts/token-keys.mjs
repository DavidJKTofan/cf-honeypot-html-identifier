#!/usr/bin/env node
/**
 * TOKEN_KEYS key-ring helper (runbook: src/identity/README.md#key-rotation).
 * Never prints key material: only key IDs.
 *
 *   npm run token-keys -- status   key IDs in .dev.vars, and which one seals new tokens
 *   npm run token-keys -- add      add a new random 32-byte key under the next ID, keeping every older key
 *   npm run token-keys -- upload   upload TOKEN_KEYS from .dev.vars to production
 *                                  (`wrangler secret put TOKEN_KEYS --env=""`, piped, never shown)
 *
 * Option: --file <path> (default .dev.vars). The ring lives on one line, TOKEN_KEYS='<json>',
 * which `.dev.vars` (dotenv) and `wrangler deploy --secrets-file` both read. Keep a copy in a
 * password manager too: Cloudflare can't show a secret again, and every rotation needs the older keys.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const LINE = /^TOKEN_KEYS='(.*)'[ \t]*$/m;
const ID = /^(0|[1-9]\d{0,2})$/;
const WIN = process.platform === "win32";

function fail(message) {
	console.error(`✘ ${message}`);
	process.exit(1);
}

/** Validate a ring and return its IDs, ascending. Errors name IDs only, never keys. */
function validate(ring) {
	if (!ring || typeof ring !== "object" || Array.isArray(ring)) fail("TOKEN_KEYS is not a JSON object");
	const ids = Object.keys(ring);
	for (const id of ids) {
		if (!ID.test(id) || Number(id) > 255) fail(`TOKEN_KEYS has an invalid key ID (must be an integer 0-255 without leading zeros)`);
		const key = ring[id];
		if (typeof key !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(key) || Buffer.from(key, "base64").length !== 32) {
			fail(`TOKEN_KEYS entry ${id} is not a base64-encoded 32-byte key`);
		}
	}
	return ids.map(Number).sort((a, b) => a - b);
}

function read(file) {
	if (!existsSync(file)) return { text: null, ring: null };
	const text = readFileSync(file, "utf8");
	const lines = text.match(new RegExp(LINE.source, "gm")) ?? [];
	if (lines.length > 1) fail(`${file} has ${lines.length} TOKEN_KEYS lines: keep exactly one`);
	const m = LINE.exec(text);
	if (!m) return { text, ring: null };
	let ring;
	try {
		ring = JSON.parse(m[1]);
	} catch {
		fail(`TOKEN_KEYS in ${file} is not valid JSON`);
	}
	validate(ring);
	return { text, ring };
}

const args = process.argv.slice(2);
const fileIdx = args.indexOf("--file");
const file = fileIdx >= 0 ? args[fileIdx + 1] : ".dev.vars";
if (!file) fail("--file needs a path");
const command = args.filter((a, i) => a !== "--file" && args[i - 1] !== "--file")[0] ?? "status";

const { text, ring } = read(file);

switch (command) {
	case "status": {
		if (!ring) {
			console.log(`No TOKEN_KEYS in ${file}: the Worker seals version 1 tokens with TOKEN_KEY (unless production has its own TOKEN_KEYS).`);
			break;
		}
		const ids = validate(ring);
		console.log(`TOKEN_KEYS in ${file}: key IDs ${ids.join(", ")}. ID ${ids.at(-1)} seals new tokens; every ID decodes.`);
		break;
	}

	case "add": {
		const next = ring ? validate(ring).at(-1) + 1 : 1;
		if (next > 255) fail("no key IDs left (0-255): see the runbook before reusing an ID");
		const updated = { ...(ring ?? {}), [String(next)]: randomBytes(32).toString("base64") };
		const line = `TOKEN_KEYS='${JSON.stringify(updated)}'`;
		let out;
		if (text === null) out = `${line}\n`;
		else if (LINE.test(text)) out = text.replace(LINE, line);
		else out = `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${line}\n`;
		writeFileSync(file, out);
		console.log(`✔ Added key ID ${next} to ${file} (IDs now ${validate(updated).join(", ")}).`);
		console.log("  1. Back up the TOKEN_KEYS line in your password manager (Cloudflare can't show it again).");
		console.log("  2. Upload it: npm run token-keys -- upload");
		console.log("  3. Check it:  npm run hp -- whoami, then npm run hp -- decode <token>  →  \"version\": 2, \"keyId\": " + next);
		break;
	}

	case "upload": {
		if (!ring) fail(`no TOKEN_KEYS in ${file}: run \`npm run token-keys -- add\` first`);
		const ids = validate(ring);
		console.log(`Uploading TOKEN_KEYS (key IDs ${ids.join(", ")}; ID ${ids.at(-1)} will seal) to the production Worker…`);
		const r = spawnSync("npx", ["--no-install", "wrangler", "secret", "put", "TOKEN_KEYS", "--env="], {
			input: JSON.stringify(ring),
			stdio: ["pipe", "inherit", "inherit"],
			shell: WIN,
		});
		if (r.status !== 0) fail("wrangler secret put failed (logged in? CLOUDFLARE_ACCOUNT_ID set?)");
		console.log(`✔ Uploaded. Check it: npm run hp -- whoami, then npm run hp -- decode <token>  →  "version": 2, "keyId": ${ids.at(-1)}`);
		break;
	}

	default:
		fail(`unknown command "${command}": use status, add or upload`);
}
