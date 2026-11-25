/**
 * Discord Interactions Endpoint: receives button clicks from approval messages.
 * https://docs.discord.com/developers/interactions/receiving-and-responding
 *
 * 1. Verify the Ed25519 signature (401 otherwise; Discord probes this).
 * 2. PING → PONG.
 * 3. Button click → check the clicker is an approver → ACK within 3 s with
 *    DEFERRED_UPDATE_MESSAGE, then run the shared approval action in
 *    waitUntil and edit the original message with the outcome.
 */
import {
	approveFlagsAction,
	approveLeadAction,
	decideCaseAction,
	dismissLeadAction,
	rejectFlagsAction,
	submitAbuseReportAction,
	type ActionResult,
	type Actor,
} from "../../approvals/actions";
import type { Config } from "../../core/config";
import { BodyTooLargeError, errorMessage, json, log, notFound, readStreamLimited } from "../../core/util";
import { discordApi } from "../index";
import { decodeAction, resolvedPayload, type ComponentAction, type RemoveMode } from "./messages";
import { verifyDiscordSignature } from "./verify";

const PING = 1;
const MESSAGE_COMPONENT = 3;
const PONG = 1;
const CHANNEL_MESSAGE_WITH_SOURCE = 4;
const DEFERRED_UPDATE_MESSAGE = 6;
const EPHEMERAL = 64;

interface Interaction {
	type: number;
	token: string;
	application_id: string;
	data?: { custom_id?: string };
	member?: { user?: { id?: string }; roles?: string[] };
	user?: { id?: string };
	message?: { id: string; embeds?: Record<string, unknown>[]; components?: { type: number; components?: { custom_id?: string }[] }[] };
}

const ephemeral = (content: string) =>
	json({ type: CHANNEL_MESSAGE_WITH_SOURCE, data: { content, flags: EPHEMERAL, allowed_mentions: { parse: [] } } });

function isApprover(cfg: Config, userId: string, roles: string[]): boolean {
	const d = cfg.notify.discord;
	return d.approverIds.has(userId) || roles.some((r) => d.approverRoleIds.has(r));
}

async function dispatch(env: Env, cfg: Config, a: ComponentAction, actor: Actor): Promise<ActionResult> {
	switch (`${a.kind}:${a.action}`) {
		case "lead:approve":
			return approveLeadAction(env, cfg, Number(a.arg), actor);
		case "lead:dismiss":
			return dismissLeadAction(env, Number(a.arg), actor);
		case "case:decoy":
		case "case:block":
		case "case:none":
			return decideCaseAction(env, a.arg, { action: a.action as "decoy" | "block" | "none" }, actor);
		case "case:abuse":
			return submitAbuseReportAction(env, cfg, a.arg, actor);
		case "flag:decoy":
		case "flag:block":
			return approveFlagsAction(env, cfg, [a.arg], { ttlDays: cfg.flagTtlDays, action: a.action as "decoy" | "block" }, actor);
		case "flag:reject":
			return rejectFlagsAction(env, [a.arg], actor);
		default:
			return { ok: false, summary: `Unknown action ${a.kind}:${a.action}` };
	}
}

function removeModeFor(a: ComponentAction, customId: string): RemoveMode {
	if (a.kind === "flag") return { type: "row", customId };
	if (a.kind === "case" && a.action === "abuse") return { type: "button", customId };
	return { type: "all" };
}

export async function handleDiscordInteraction(request: Request, env: Env, ctx: ExecutionContext, cfg: Config): Promise<Response> {
	const d = cfg.notify.discord;
	if (!d.publicKey) return notFound();

	let raw: string;
	try {
		raw = new TextDecoder().decode(await readStreamLimited(request.body, 64 * 1024));
	} catch (err) {
		return new Response(err instanceof BodyTooLargeError ? "payload too large" : "bad request", { status: 400 });
	}
	const valid = await verifyDiscordSignature(d.publicKey, request.headers.get("x-signature-ed25519"), request.headers.get("x-signature-timestamp"), raw);
	if (!valid) return new Response("invalid request signature", { status: 401 });

	let i: Interaction;
	try {
		i = JSON.parse(raw) as Interaction;
	} catch {
		return new Response("bad request", { status: 400 });
	}
	if (i.type === PING) return json({ type: PONG });
	if (i.type !== MESSAGE_COMPONENT) return ephemeral("Unsupported interaction.");

	const customId = i.data?.custom_id ?? "";
	const action = decodeAction(customId);
	if (!action) return ephemeral("Unknown button.");

	const userId = i.member?.user?.id ?? i.user?.id ?? "";
	const approver = isApprover(cfg, userId, i.member?.roles ?? []);

	if (action.kind === "test") {
		return ephemeral(
			`Interactions endpoint works. Your user ID is \`${userId}\`: ` +
				(approver ? "you **can** approve honeypot actions." : "you are **not** an approver (add it to DISCORD_APPROVER_IDS)."),
		);
	}
	if (!approver) {
		log("warn", "discord: unauthorized click", { userId, customId });
		return ephemeral("You are not allowed to approve honeypot actions (DISCORD_APPROVER_IDS / DISCORD_APPROVER_ROLE_IDS).");
	}

	const actor: Actor = { id: `discord:${userId}`, label: `<@${userId}>` };
	const api = discordApi(env, cfg);
	ctx.waitUntil(
		(async () => {
			try {
				const result = await dispatch(env, cfg, action, actor);
				const summary = `${result.ok ? "Done" : "Not applied"}: ${result.summary}`;
				await api.editOriginal(i.application_id, i.token, resolvedPayload(i.message ?? null, summary, removeModeFor(action, customId)));
			} catch (err) {
				log("error", "discord: action failed", { customId, error: errorMessage(err) });
				await api.followup(i.application_id, i.token, `Action failed: ${errorMessage(err).slice(0, 300)}. Lead approvals and case decisions roll back; a flag approval may be partly applied. Check with the CLI (for example \`npm run hp -- flags active\`) before retrying.`);
			}
		})(),
	);
	return json({ type: DEFERRED_UPDATE_MESSAGE });
}
