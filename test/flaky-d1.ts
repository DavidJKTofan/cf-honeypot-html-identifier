/**
 * Test helper: a D1Database whose first `failures` write executions throw a transient D1 error
 * BEFORE reaching the database (nothing is written), like a reset Durable Object. Reads always
 * pass through. Used to check that the admin API and Discord callbacks retry their writes.
 */
import { isWriteSql } from "../src/storage/retry";

export const NETWORK_LOST = "D1_ERROR: Network connection lost.";

export function flakyD1(db: D1Database, failures: number, message = NETWORK_LOST) {
	let left = failures;
	const state = { thrown: 0, writes: 0 };
	const real = new WeakMap<object, { stmt: D1PreparedStatement; write: boolean }>();
	const maybeFail = () => {
		state.writes++;
		if (left > 0) {
			left--;
			state.thrown++;
			throw new Error(message);
		}
	};
	const wrap = (stmt: D1PreparedStatement, write: boolean): D1PreparedStatement => {
		const proxy = new Proxy(stmt, {
			get(target, prop) {
				if (prop === "bind") return (...v: unknown[]) => wrap(target.bind(...v), write);
				const value: unknown = Reflect.get(target, prop, target);
				if (typeof value !== "function") return value;
				const fn = value as (...a: unknown[]) => Promise<unknown>;
				if (write && (prop === "run" || prop === "first" || prop === "all" || prop === "raw")) {
					return async (...a: unknown[]) => {
						maybeFail();
						return fn.apply(target, a);
					};
				}
				return (...a: unknown[]) => fn.apply(target, a);
			},
		});
		real.set(proxy, { stmt, write });
		return proxy;
	};
	const flaky = new Proxy(db, {
		get(target, prop) {
			if (prop === "prepare") return (sql: string) => wrap(target.prepare(sql), isWriteSql(sql));
			if (prop === "batch") {
				return async (stmts: D1PreparedStatement[]) => {
					if (stmts.some((s) => real.get(s)?.write ?? true)) maybeFail();
					return target.batch(stmts.map((s) => real.get(s)?.stmt ?? s));
				};
			}
			const value: unknown = Reflect.get(target, prop, target);
			return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
		},
	});
	return { db: flaky, state };
}
