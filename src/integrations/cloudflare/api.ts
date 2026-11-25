/**
 * Minimal Cloudflare REST client for the services that have no Workers binding:
 * WAF Lists, Threat Intel, URL Scanner and Brand Protection.
 * (Best practice is "bindings, not REST"; these are the exceptions.)
 *
 * Requires the optional CF_API_TOKEN secret, scoped to:
 *   Account Filter Lists Edit · Intel Read · URL Scanner Edit
 * Without it, cfApi() returns null and callers mark their step "skipped".
 *
 * Retries: 429 is always retried (the request was rejected, not processed). 5xx and
 * network errors are retried only for idempotent calls (GET, DELETE, and list-item
 * writes, which upsert). Backoff is exponential with jitter, honours `retry-after`,
 * and is bounded by a per-call time budget so request paths stay inside their
 * waitUntil / response deadlines.
 * Lists API rate limits: https://developers.cloudflare.com/waf/tools/lists/lists-api/#rate-limiting-for-lists-api-requests
 */
import { randomInt } from "../../core/util";
import { canonicalIp } from "../../identity/token";

const BASE = "https://api.cloudflare.com/client/v4";

export class CfApiError extends Error {
	constructor(
		message: string,
		readonly status: number,
	) {
		super(message);
	}
}

interface Envelope<T> {
	success?: boolean;
	errors?: { code: number; message: string }[];
	result?: T;
	result_info?: { cursors?: { after?: string } };
}

export interface ListItem {
	id: string;
	ip?: string;
	comment?: string;
}

/** Status of an asynchronous Lists bulk operation (`timeout` = still pending/running when the budget ran out). */
export interface ListOperationResult {
	status: "completed" | "failed" | "timeout";
	error?: string;
}

export interface BrandQuery {
	query_id: number;
	query_tag?: string;
}

export interface BrandLogo {
	id: number;
	tag?: string;
}

export interface BrandMatch {
	domain?: string;
	first_seen?: string;
	[key: string]: unknown;
}

export interface CfApiOptions {
	/** Injected for tests; defaults to the global fetch. */
	fetcher?: typeof fetch;
	/** Injected for tests; defaults to scheduler.wait. */
	sleep?: (ms: number) => Promise<void>;
	/** Per-attempt timeout (default 20 s). */
	timeoutMs?: number;
	/** Total time one call may spend on attempts and backoff (default 30 s). */
	retryBudgetMs?: number;
	/** Maximum attempts per call, including the first (default 4). */
	maxAttempts?: number;
	/** First backoff delay (default 500 ms); doubles per attempt. */
	baseDelayMs?: number;
	/** Largest single backoff delay (default 8 s). A longer `retry-after` stops retrying. */
	maxDelayMs?: number;
}

interface CallOptions {
	query?: Record<string, string | number>;
	body?: unknown;
	/** Safe to repeat after a 5xx or network error (same effect twice). */
	idempotent?: boolean;
}

const RETRYABLE_5XX = new Set([500, 502, 503, 504]);

/** Seconds or HTTP-date → milliseconds; null if absent or unparseable. */
function retryAfterMs(header: string | null, now: number): number | null {
	if (!header) return null;
	const secs = Number(header);
	if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
	const at = Date.parse(header);
	return Number.isFinite(at) ? Math.max(0, at - now) : null;
}

export class CfApi {
	private readonly fetcher: typeof fetch;
	private readonly sleep: (ms: number) => Promise<void>;
	private readonly timeoutMs: number;
	private readonly retryBudgetMs: number;
	private readonly maxAttempts: number;
	private readonly baseDelayMs: number;
	private readonly maxDelayMs: number;

	constructor(
		private readonly token: string,
		private readonly accountId: string,
		opts: CfApiOptions = {},
	) {
		this.fetcher = opts.fetcher ?? ((input, init) => fetch(input, init));
		this.sleep = opts.sleep ?? ((ms) => scheduler.wait(ms));
		this.timeoutMs = opts.timeoutMs ?? 20_000;
		this.retryBudgetMs = opts.retryBudgetMs ?? 30_000;
		this.maxAttempts = Math.max(1, opts.maxAttempts ?? 4);
		this.baseDelayMs = opts.baseDelayMs ?? 500;
		this.maxDelayMs = opts.maxDelayMs ?? 8_000;
	}

	/** Backoff before attempt `n + 1` (n ≥ 1): exponential with "equal jitter". */
	private backoff(n: number): number {
		const exp = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** (n - 1));
		const half = Math.floor(exp / 2);
		return half + randomInt(half + 1);
	}

	private async raw(method: string, path: string, opts: CallOptions = {}): Promise<Response> {
		const url = new URL(`${BASE}/accounts/${this.accountId}${path}`);
		for (const [k, v] of Object.entries(opts.query ?? {})) url.searchParams.set(k, String(v));
		const retryable = opts.idempotent ?? (method === "GET" || method === "DELETE");
		const deadline = Date.now() + this.retryBudgetMs;

		for (let attempt = 1; ; attempt++) {
			const remaining = deadline - Date.now();
			let res: Response | null = null;
			let failure: unknown = null;
			try {
				res = await this.fetcher(url, {
					method,
					headers: {
						authorization: `Bearer ${this.token}`,
						...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
					},
					body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
					signal: AbortSignal.timeout(Math.max(1_000, Math.min(this.timeoutMs, remaining))),
				});
			} catch (err) {
				failure = err;
			}

			const shouldRetry = res ? res.status === 429 || (retryable && RETRYABLE_5XX.has(res.status)) : retryable;
			if (!shouldRetry || attempt >= this.maxAttempts) {
				if (res) return res;
				throw failure;
			}

			const hinted = res ? retryAfterMs(res.headers.get("retry-after"), Date.now()) : null;
			const delay = hinted ?? this.backoff(attempt);
			// A server-requested wait longer than we allow, or past the budget: give up now.
			if (hinted !== null && hinted > this.maxDelayMs) {
				if (res) return res;
				throw failure;
			}
			if (Date.now() + delay >= deadline) {
				if (res) return res;
				throw failure;
			}
			await res?.body?.cancel();
			await this.sleep(delay);
		}
	}

	private async call<T>(method: string, path: string, opts: CallOptions = {}): Promise<Envelope<T> | T | null> {
		const res = await this.raw(method, path, opts);
		const text = await res.text();
		let data: unknown = null;
		try {
			data = text ? JSON.parse(text) : null;
		} catch {
			// non-JSON error body
		}
		if (!res.ok) {
			const env = data as Envelope<unknown> | null;
			const detail = env?.errors?.map((e) => `${e.code}: ${e.message}`).join("; ") || text.slice(0, 200);
			throw new CfApiError(`${method} ${path} → ${res.status} ${detail}`, res.status);
		}
		return data as Envelope<T> | T | null;
	}

	/**
	 * JSON request. Unwraps the standard `{ success, result }` envelope unless
	 * `bare` is set: URL Scanner v2 returns bare JSON whose own `result` field is
	 * the report URL, so it must not be unwrapped.
	 */
	async request<T>(method: string, path: string, opts: CallOptions & { bare?: boolean } = {}): Promise<T> {
		const data = await this.call<T>(method, path, opts);
		if (opts.bare) return data as T;
		const env = data as Envelope<T> | null;
		return (env && typeof env === "object" && "success" in env && "result" in env ? env.result : data) as T;
	}

	// ------------------------------------------------------------ WAF Lists
	/** Asynchronous upsert ("update items already in the list, add the others"); returns the operation id. */
	async addListItems(listId: string, items: { ip: string; comment: string }[]): Promise<string> {
		const r = await this.request<{ operation_id: string }>("POST", `/rules/lists/${listId}/items`, { body: items, idempotent: true });
		return r.operation_id;
	}

	async findListItem(listId: string, ip: string): Promise<ListItem | null> {
		const items = await this.request<ListItem[]>("GET", `/rules/lists/${listId}/items`, {
			query: { search: ip, per_page: 50 },
		});
		const want = canonicalIp(ip) ?? ip;
		return items.find((i) => typeof i.ip === "string" && (canonicalIp(i.ip) ?? i.ip) === want) ?? null;
	}

	/** One page of list items (`per_page` ≤ 500) and the cursor for the next page, if any. */
	async listItemsPage(listId: string, cursor?: string, perPage = 500): Promise<{ items: ListItem[]; next: string | null }> {
		const env = (await this.call<ListItem[]>("GET", `/rules/lists/${listId}/items`, {
			query: { per_page: perPage, ...(cursor ? { cursor } : {}) },
		})) as Envelope<ListItem[]> | null;
		return { items: env?.result ?? [], next: env?.result_info?.cursors?.after ?? null };
	}

	async deleteListItems(listId: string, ids: string[]): Promise<string | null> {
		if (ids.length === 0) return null;
		const r = await this.request<{ operation_id: string }>("DELETE", `/rules/lists/${listId}/items`, {
			body: { items: ids.map((id) => ({ id })) },
		});
		return r.operation_id;
	}

	async listOperationStatus(operationId: string): Promise<{ status: string; error?: string }> {
		const r = await this.request<{ status: string; error?: string }>("GET", `/rules/lists/bulk_operations/${operationId}`);
		return { status: r.status, ...(r.error ? { error: r.error } : {}) };
	}

	/**
	 * Poll a bulk operation until it is `completed` or `failed`, or `budgetMs` runs out
	 * (then `timeout`: the operation is accepted and still queued, not known to have failed).
	 * Status values: pending · running · completed · failed.
	 */
	async waitForListOperation(operationId: string, budgetMs: number): Promise<ListOperationResult> {
		const deadline = Date.now() + budgetMs;
		let interval = 250;
		for (;;) {
			const op = await this.listOperationStatus(operationId);
			if (op.status === "completed") return { status: "completed" };
			if (op.status === "failed") return { status: "failed", error: op.error ?? "bulk operation failed" };
			if (Date.now() + interval >= deadline) return { status: "timeout" };
			await this.sleep(interval);
			interval = Math.min(2_000, interval * 2);
		}
	}

	// ------------------------------------------------------------ Threat Intel
	intelDomain(domain: string): Promise<unknown> {
		return this.request("GET", "/intel/domain", { query: { domain } });
	}

	intelWhois(domain: string): Promise<unknown> {
		return this.request("GET", "/intel/whois", { query: { domain } });
	}

	intelIp(ip: string): Promise<unknown> {
		return this.request("GET", "/intel/ip", { query: ip.includes(":") ? { ipv6: ip } : { ipv4: ip } });
	}

	// ------------------------------------------------------------ URL Scanner
	async urlscanSubmit(url: string, visibility: "Unlisted" | "Public"): Promise<{ uuid: string; result?: string }> {
		const r = await this.request<{ uuid?: string; result?: string }>("POST", "/urlscanner/v2/scan", {
			body: { url, visibility },
			bare: true,
		});
		if (!r?.uuid) throw new CfApiError("URL Scanner did not return a scan uuid", 502);
		return { uuid: r.uuid, result: r.result };
	}

	/** Returns null while the scan is still running (404). */
	async urlscanResult(uuid: string): Promise<Record<string, unknown> | null> {
		try {
			return await this.request<Record<string, unknown>>("GET", `/urlscanner/v2/result/${uuid}`, { bare: true });
		} catch (err) {
			if (err instanceof CfApiError && err.status === 404) return null;
			throw err;
		}
	}

	async urlscanScreenshot(uuid: string): Promise<ArrayBuffer | null> {
		const res = await this.raw("GET", `/urlscanner/v2/screenshots/${uuid}.png`);
		if (!res.ok) {
			await res.body?.cancel();
			return null;
		}
		return res.arrayBuffer();
	}

	// ------------------------------------------------------------ Abuse reports (Trust and Safety Write)
	/** Never retried on 5xx: a legal report must not be filed twice. */
	submitAbuseReport(reportParam: string, body: Record<string, unknown>): Promise<unknown> {
		return this.request("POST", `/abuse-reports/${encodeURIComponent(reportParam)}`, { body, bare: true, idempotent: false });
	}

	// ------------------------------------------------------------ Brand Protection
	brandQueries(): Promise<BrandQuery[]> {
		return this.request("GET", "/brand-protection/queries");
	}

	async brandMatches(queryId: number, limit: number): Promise<BrandMatch[]> {
		const r = await this.request<{ matches?: BrandMatch[] }>("GET", "/brand-protection/matches", {
			query: { id: queryId, limit, offset: 0 },
		});
		return r.matches ?? [];
	}

	brandLogos(): Promise<BrandLogo[]> {
		return this.request("GET", "/brand-protection/logos");
	}

	async brandLogoMatches(logoId: number, limit: number): Promise<BrandMatch[]> {
		const r = await this.request<{ matches?: BrandMatch[] }>("GET", "/brand-protection/logo-matches", {
			query: { logo_id: logoId, limit, offset: 0 },
		});
		return r.matches ?? [];
	}
}

export function cfApi(env: Env, opts: CfApiOptions = {}): CfApi | null {
	const token = env.CF_API_TOKEN;
	const accountId = (env.ACCOUNT_ID ?? "").trim();
	return token && accountId ? new CfApi(token, accountId, opts) : null;
}
