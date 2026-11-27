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
/**
 * A Worker secret holds at most 5 KB (https://developers.cloudflare.com/workers/platform/limits/#environment-variables),
 * counted conservatively as 5,000 bytes: about 95 keys at roughly 52 bytes each. A Secrets Store
 * secret holds 64 KB (all 256 IDs); its users update the store secret instead of running `upload`.
 */
const WORKER_SECRET_BYTES = 5_000;
const WARN_BYTES = 4_500;
const BYTES_PER_KEY = 53;
const ringBytes = (ring) => Buffer.byteLength(JSON.stringify(ring), "utf8");

/** One line on how full the ring is, as a Worker secret. */
function sizeNote(ring) {
	const bytes = ringBytes(ring);
	const room = Math.max(0, Math.floor((WORKER_SECRET_BYTES - bytes) / BYTES_PER_KEY));
	if (bytes > WORKER_SECRET_BYTES) {
		return `⚠ ${bytes} bytes: too large for a Worker secret (5 KB). Move the ring to Secrets Store (64 KB), or remove IDs whose copies you accept losing (runbook step 6).`;
	}
	const note = `${bytes} of ${WORKER_SECRET_BYTES} bytes as a Worker secret (room for about ${room} more key${room === 1 ? "" : "s"}).`;
	return bytes > WARN_BYTES ? `⚠ ${note} Plan the move to Secrets Store (64 KB) soon.` : note;
}

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
		console.log(`Size: ${sizeNote(ring)}`);
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
		console.log(`  Size: ${sizeNote(updated)}`);
		console.log("  1. Back up the TOKEN_KEYS line in your password manager (Cloudflare can't show it again).");
		console.log("  2. Upload it: npm run token-keys -- upload");
		console.log("  3. Check it:  npm run hp -- whoami, then npm run hp -- decode <token>  →  \"version\": 2, \"keyId\": " + next);
		break;
	}

	case "upload": {
		if (!ring) fail(`no TOKEN_KEYS in ${file}: run \`npm run token-keys -- add\` first`);
		const ids = validate(ring);
		if (ringBytes(ring) > WORKER_SECRET_BYTES) {
			fail(`the ring is ${ringBytes(ring)} bytes, over the 5 KB Worker secret limit: put it in Secrets Store (src/identity/README.md#secrets-store) or remove IDs whose copies you accept losing`);
		}
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
