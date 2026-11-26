import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import spec from "../src/admin/openapi.yaml?raw";
import { handleAdmin } from "../src/admin/router";
import { loadConfig } from "../src/core/config";

/** "METHOD /path" for every operation in the spec (line-based: two-space paths, four-space methods). */
function operations(yaml: string): string[] {
	const out: string[] = [];
	let inPaths = false;
	let path = "";
	for (const line of yaml.split("\n")) {
		if (/^\S/.test(line)) inPaths = line.startsWith("paths:");
		if (!inPaths) continue;
		const p = /^ {2}(\/\S*):\s*$/.exec(line);
		if (p?.[1]) path = p[1];
		const m = /^ {4}(get|post|put|patch|delete):\s*$/.exec(line);
		if (m?.[1] && path) out.push(`${m[1].toUpperCase()} ${path}`);
	}
	return out;
}

const PLACEHOLDERS: Record<string, string> = { id: "999999", file: "report.json", indicator: encodeURIComponent("ip:203.0.113.250") };
const cfg = loadConfig(env); // no Access configured in tests: bearer auth

async function call(method: string, path: string): Promise<{ status: number; body: unknown }> {
	const url = `https://honeypot.automatic-demo.com/__hp${path.replace(/\{(\w+)\}/g, (_, name: string) => PLACEHOLDERS[name] ?? "x")}`;
	const init: RequestInit = { method, headers: { authorization: "Bearer test-admin-token", "content-type": "application/json" } };
	if (method === "POST") init.body = "{}";
	const res = await handleAdmin(new Request(url, init), env, createExecutionContext(), cfg);
	const text = await res.text();
	let body: unknown = text;
	try {
		body = JSON.parse(text);
	} catch {
		// plain text
	}
	return { status: res.status, body };
}

describe("OpenAPI spec (src/admin/openapi.yaml)", () => {
	const ops = operations(spec);

	it("documents every admin operation", () => {
		expect(spec.startsWith("openapi: 3.1.0")).toBe(true);
		expect(ops).toHaveLength(21);
		expect(new Set(ops).size).toBe(ops.length);
	});

	it("the router recognises an undocumented path as unknown (so the next check means something)", async () => {
		expect(await call("GET", "/definitely-not-a-route")).toMatchObject({ status: 404, body: { error: "unknown admin route" } });
	});

	// Starting a maintenance Workflow from a test has side effects; it's covered by the spec count above.
	it.each(ops.filter((o) => o !== "POST /maintenance/run"))("%s is routed by the Worker", async (op) => {
		const [method = "", path = ""] = op.split(" ");
		const res = await call(method, path);
		expect(res.body).not.toEqual({ error: "unknown admin route" });
	});
});
