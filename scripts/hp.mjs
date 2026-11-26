#!/usr/bin/env node
/**
 * Tiny admin CLI for cf-honeypot-html-identifier.
 *
 *   HP_BASE                  default https://honeypot.automatic-demo.com
 *   HP_ACCESS_CLIENT_ID      Cloudflare Access service token (env, or ./.env); required once
 *   HP_ACCESS_CLIENT_SECRET  Access protects ADMIN_PREFIX (see src/admin/README.md)
 *   HP_ADMIN_TOKEN           bearer token; default: ADMIN_TOKEN read from ./.dev.vars. Needed
 *                            only when the Worker has no Access configuration (local dev)
 *
 * Keep the service token in .env (gitignored), never in .dev.vars: `wrangler deploy
 * --secrets-file .dev.vars` would upload it to the Worker as a secret it doesn't need.
 *
 * Usage: node scripts/hp.mjs <command> [...args]   (or: npm run hp -- <command> ...)
 */
import { existsSync, readFileSync } from "node:fs";

const BASE = (process.env.HP_BASE ?? "https://honeypot.automatic-demo.com").replace(/\/+$/, "");
const PREFIX = process.env.HP_PREFIX ?? "/__hp";

/** A value from the environment, else from a dotenv-style file in the working directory. */
function setting(envName, file, fileName = envName) {
	if (process.env[envName]) return process.env[envName];
	if (!existsSync(file)) return null;
	const m = new RegExp(`^${fileName}\\s*=\\s*"?([^"\\n]+)"?`, "m").exec(readFileSync(file, "utf8"));
	return m ? m[1].trim() : null;
}

function authHeaders() {
	const headers = {};
	const id = setting("HP_ACCESS_CLIENT_ID", ".env");
	const secret = setting("HP_ACCESS_CLIENT_SECRET", ".env");
	if (id && secret) {
		headers["cf-access-client-id"] = id;
		headers["cf-access-client-secret"] = secret;
	}
	const bearer = setting("HP_ADMIN_TOKEN", ".dev.vars", "ADMIN_TOKEN");
	if (bearer) headers.authorization = `Bearer ${bearer}`;
	if (Object.keys(headers).length === 0) {
		console.error("No credentials: set HP_ACCESS_CLIENT_ID/HP_ACCESS_CLIENT_SECRET (in .env) or ADMIN_TOKEN (in .dev.vars).");
		process.exit(2);
	}
	return headers;
}

/**
 * The zone's WAF runs before the Worker, so an admin call can be challenged (e.g. a
 * "WAF Attack Score" rule scoring a pasted page) or blocked (e.g. your IP is in the
 * honeypot_blocked list). Say so plainly instead of printing a challenge page.
 */
function edgeVerdict(res, type) {
	const ray = res.headers.get("cf-ray") ?? "n/a";
	const mitigated = res.headers.get("cf-mitigated");
	const location = res.headers.get("location") ?? "";
	// Access answers an unauthenticated request with a redirect to the login page, or 401/403
	// for a service token it rejects (service_auth_401_redirect).
	if (res.status >= 300 && res.status < 400 && location.includes("cloudflareaccess.com")) {
		return `Cloudflare Access requires authentication for ${PREFIX}/* (Ray ${ray}). Set HP_ACCESS_CLIENT_ID and HP_ACCESS_CLIENT_SECRET (service token) in .env. See src/admin/README.md.`;
	}
	if ((res.status === 401 || res.status === 403) && res.headers.has("cf-access-domain")) {
		return `Cloudflare Access rejected the service token (HTTP ${res.status}, Ray ${ray}). Check HP_ACCESS_CLIENT_ID/HP_ACCESS_CLIENT_SECRET, the token's expiry, and that the app's service-auth policy includes it.`;
	}
	// Challenge responses carry `cf-mitigated: challenge`:
	// https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
	if (mitigated === "challenge") {
		return `Cloudflare challenged this admin request before it reached the Worker (Ray ${ray}). A zone WAF rule matched it, often an attack-score rule on a pasted page. Check Security Events for this Ray, then add a narrow skip rule for ${PREFIX}/* or put Cloudflare Access (service token) in front of it. See src/admin/README.md.`;
	}
	if (res.status === 403 && !type.includes("json")) {
		return `Blocked at the edge with HTTP 403 (Ray ${ray}). If your own IP was approved for blocking (honeypot_blocked list), remove that list item in the dashboard or with the Cloudflare API; the admin API itself is reachable as soon as the edge lets you through.`;
	}
	return null;
}

async function call(method, path, body) {
	const res = await fetch(`${BASE}${PREFIX}${path}`, {
		method,
		headers: { ...authHeaders(), "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
		redirect: "manual",
	});
	const type = res.headers.get("content-type") ?? "";
	const verdict = edgeVerdict(res, type);
	if (verdict) {
		await res.body?.cancel();
		console.error(verdict);
		process.exitCode = 1;
		return;
	}
	const out = type.includes("json") ? JSON.stringify(await res.json(), null, 2) : await res.text();
	console.log(out);
	if (!res.ok) process.exitCode = 1;
}

const [cmd, ...args] = process.argv.slice(2);
const enc = encodeURIComponent;

const commands = {
	whoami: () => call("GET", "/whoami"),
	decode: ([input]) => {
		if (!input) throw new Error("decode <url | file.html | token>");
		if (/^https?:\/\//.test(input)) return call("POST", "/decode", { url: input });
		// Base64 so the zone's WAF managed rules don't block pasted <script> markup.
		if (existsSync(input)) return call("POST", "/decode", { html_b64: readFileSync(input).toString("base64") });
		return call("POST", "/decode", { token: input });
	},
	leads: ([status = "pending"]) => call("GET", `/leads?status=${enc(status)}`),
	"approve-lead": ([id, url]) => call("POST", `/leads/${enc(id)}/approve`, url ? { url } : {}),
	"dismiss-lead": ([id]) => call("POST", `/leads/${enc(id)}/dismiss`),
	case: ([url]) => call("POST", "/cases", { url }),
	cases: () => call("GET", "/cases"),
	"case-status": ([id]) => call("GET", `/cases/${enc(id)}`),
	report: ([id, format]) => call("GET", `/cases/${enc(id)}/report${format === "json" ? "?format=json" : ""}`),
	decide: ([id, action, ttlDays]) =>
		call("POST", `/cases/${enc(id)}/decision`, { action, ...(ttlDays ? { ttlDays: Number(ttlDays) } : {}) }),
	flags: ([status]) => call("GET", `/flags${status ? `?status=${enc(status)}` : ""}`),
	"approve-flags": (a) => {
		const all = a.includes("--all");
		const block = a.includes("--block");
		const indicators = a.filter((x) => !x.startsWith("--"));
		return call("POST", "/flags/approve", { ...(all ? { all: true } : { indicators }), ...(block ? { action: "block" } : {}) });
	},
	"reject-flags": (indicators) => call("POST", "/flags/reject", { indicators }),
	flag: ([ip, action = "decoy", ttlDays]) =>
		call("POST", "/flags", { ip, action, reason: "manual (cli)", ...(ttlDays ? { ttlDays: Number(ttlDays) } : {}) }),
	unflag: ([indicator]) => call("DELETE", `/flags/${enc(indicator)}`),
	"abuse-report": ([id]) => call("POST", `/cases/${enc(id)}/abuse-report`),
	"abuse-report-reset": ([id]) => call("POST", `/cases/${enc(id)}/abuse-report/reset`),
	evidence: ([id, file]) => call("GET", `/cases/${enc(id)}/evidence/${enc(file)}`),
	"notify-test": () => call("POST", "/notify/test"),
	"notify-flags": () => call("POST", "/notify/flags"),
	maintenance: () => call("POST", "/maintenance/run"),
};

if (!cmd || !(cmd in commands)) {
	console.log(`Commands: ${Object.keys(commands).join(", ")}`);
	process.exit(cmd ? 2 : 0);
}
await commands[cmd](args);
