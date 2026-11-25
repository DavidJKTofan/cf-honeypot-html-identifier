/** Shared request context and helpers for admin route modules. */
import type { Actor } from "../approvals/actions";
import type { Config } from "../core/config";
import { json } from "../core/util";

export interface AdminContext {
	request: Request;
	env: Env;
	ctx: ExecutionContext;
	cfg: Config;
	url: URL;
	method: string;
	/** Path below ADMIN_PREFIX, e.g. "/cases/case-123/decision". */
	path: string;
	seg: string[];
	actor: Actor;
}

/** A route module returns a Response when it handles the request, otherwise null. */
export type AdminRoute = (c: AdminContext) => Promise<Response | null>;

/** Bearer-token caller (local dev, or no Access app). With Access, the actor is the JWT identity. */
export const ADMIN_ACTOR: Actor = { id: "admin", label: "admin API" };

export function badRequest(message: string): Response {
	return json({ error: message }, { status: 400 });
}

export function ttlFrom(value: unknown, fallback: number): number {
	return typeof value === "number" && value > 0 ? Math.min(365, Math.floor(value)) : fallback;
}
