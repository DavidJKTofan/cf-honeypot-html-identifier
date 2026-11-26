/**
 * Retries for D1 writes on the request paths that humans drive: the admin API and Discord
 * button callbacks. D1 retries read-only queries itself, but never writes:
 * https://developers.cloudflare.com/d1/best-practices/retry-queries/
 *
 * Only the transient errors the D1 guide names are retried, with jittered exponential
 * backoff and at most 5 attempts. Everything else (a constraint violation, bad SQL) throws
 * at once.
 *
 * Why retrying these writes is safe: every approval claim is a conditional
 * `UPDATE … WHERE status = …`, and the other writes are upserts or conditional deletes. A
 * retry never applies an action twice. If an attempt committed but its answer was lost
 * ("Network connection lost" can arrive after the commit), the retry reports "no change",
 * so the caller says "already handled" instead of acting a second time: the same state a
 * failed call without retries leaves behind.
 *
 * Workflows don't use this: their steps have their own retries. The hot path doesn't
 * either: it only reads, through a session.
 */
import { errorMessage, log, randomInt } from "../core/util";

/** The transient D1 errors that are safe to retry (D1 guide, "Retry queries"). */
const RETRYABLE = ["Network connection lost", "storage caused object to be reset", "reset because its code was updated"] as const;

export function isRetryableD1Error(err: unknown): boolean {
	const message = errorMessage(err);
	return RETRYABLE.some((m) => message.includes(m));
}

export interface D1RetryOptions {
	/** Attempts including the first (default 5, the guide's maximum). */
	maxAttempts?: number;
	/** Delay before the second attempt (default 100 ms); doubles per attempt. */
	baseDelayMs?: number;
	/** Largest single delay (default 2 s). */
	maxDelayMs?: number;
	/** Injected for tests; defaults to scheduler.wait. */
	sleep?: (ms: number) => Promise<void>;
}

/** Backoff before attempt `n + 1` (n ≥ 1): exponential with "equal jitter". */
function backoff(n: number, base: number, max: number): number {
	const exp = Math.min(max, base * 2 ** (n - 1));
	const half = Math.floor(exp / 2);
	return half + randomInt(half + 1);
}

/** Run `op`, retrying only the transient D1 errors above. */
export async function retryD1<T>(op: () => Promise<T>, opts: D1RetryOptions = {}): Promise<T> {
	const maxAttempts = Math.max(1, Math.min(5, opts.maxAttempts ?? 5));
	const base = opts.baseDelayMs ?? 100;
	const max = opts.maxDelayMs ?? 2_000;
	const sleep = opts.sleep ?? ((ms: number) => scheduler.wait(ms));
	for (let attempt = 1; ; attempt++) {
		try {
			return await op();
		} catch (err) {
			if (attempt >= maxAttempts || !isRetryableD1Error(err)) throw err;
			const delay = backoff(attempt, base, max);
			log("warn", "d1: transient write error, retrying", { attempt, delayMs: delay, error: errorMessage(err) });
			await sleep(delay);
		}
	}
}

/**
 * True unless the statement only reads (SELECT, EXPLAIN, VALUES, or WITH without a write).
 * Unknown statements count as writes: retrying a read is harmless, skipping a write isn't.
 */
export function isWriteSql(sql: string): boolean {
	const first = /^\s*([A-Za-z]+)/.exec(sql)?.[1]?.toUpperCase();
	if (first === "SELECT" || first === "EXPLAIN" || first === "VALUES") return false;
	if (first === "WITH") return /\b(INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql);
	return true;
}

const EXEC_METHODS = new Set(["run", "first", "all", "raw"]);

/**
 * A D1Database whose write statements retry transient errors (`retryD1`). Reads go through
 * unchanged (D1 retries them), so do `withSession` and `exec`. A `batch` is one transaction:
 * it is retried as a whole when any statement in it writes.
 */
export function withD1WriteRetries(db: D1Database, opts: D1RetryOptions = {}): D1Database {
	// Wrapped statement → the real one (D1's batch() only accepts its own statements) and whether it writes.
	const inner = new WeakMap<object, { stmt: D1PreparedStatement; write: boolean }>();

	const wrap = (stmt: D1PreparedStatement, write: boolean): D1PreparedStatement => {
		const proxy = new Proxy(stmt, {
			get(target, prop) {
				if (prop === "bind") return (...values: unknown[]) => wrap(target.bind(...values), write);
				const value: unknown = Reflect.get(target, prop, target);
				if (typeof value !== "function") return value;
				const fn = value as (...a: unknown[]) => Promise<unknown>;
				if (write && typeof prop === "string" && EXEC_METHODS.has(prop)) {
					return (...a: unknown[]) => retryD1(() => fn.apply(target, a), opts);
				}
				return (...a: unknown[]) => fn.apply(target, a);
			},
		});
		inner.set(proxy, { stmt, write });
		return proxy;
	};

	return new Proxy(db, {
		get(target, prop) {
			if (prop === "prepare") return (sql: string) => wrap(target.prepare(sql), isWriteSql(sql));
			if (prop === "batch") {
				return <T>(stmts: D1PreparedStatement[]) => {
					const real = stmts.map((s) => inner.get(s)?.stmt ?? s);
					const write = stmts.some((s) => inner.get(s)?.write ?? true);
					return write ? retryD1(() => target.batch<T>(real), opts) : target.batch<T>(real);
				};
			}
			const value: unknown = Reflect.get(target, prop, target);
			return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
		},
	});
}

/**
 * `env` with `DB` wrapped by `withD1WriteRetries`. The admin router and the Discord
 * interactions endpoint pass this to every action, so each write behind them retries.
 */
export function envWithD1WriteRetries(env: Env, opts: D1RetryOptions = {}): Env {
	return { ...env, DB: withD1WriteRetries(env.DB, opts) };
}
