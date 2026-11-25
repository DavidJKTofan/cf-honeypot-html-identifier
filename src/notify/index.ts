/**
 * Notifier factory + safe helpers. Notifications never break the request or
 * Workflow that triggers them, and are rate-limited (NOTIFY_LIMITER) so a burst
 * of leads cannot flood the channel.
 */
import type { Config } from "../core/config";
import { errorMessage, log } from "../core/util";
import { DiscordApi } from "./discord/api";
import { DiscordBotNotifier, DiscordWebhookNotifier } from "./discord/notifier";
import type { LeadNotice, Notifier, NotifyRef } from "./types";

export type { CaseNotice, FlagNotice, LeadNotice, Notifier, NotifyRef } from "./types";

export function discordApi(env: Env, cfg: Config): DiscordApi {
	return new DiscordApi(cfg.notify.discord.apiBase, env.DISCORD_BOT_TOKEN ?? null);
}

/** Returns null when the configured channel is missing credentials (notifications disabled). */
export function getNotifier(env: Env, cfg: Config): Notifier | null {
	switch (cfg.notify.channel) {
		case "discord":
			return env.DISCORD_BOT_TOKEN && cfg.notify.discord.channelId
				? new DiscordBotNotifier(discordApi(env, cfg), cfg.notify.discord.channelId)
				: null;
		case "discord-webhook":
			return env.DISCORD_WEBHOOK_URL ? new DiscordWebhookNotifier(env.DISCORD_WEBHOOK_URL) : null;
		default:
			return null;
	}
}

export async function notifySafe(
	env: Env,
	cfg: Config,
	label: string,
	send: (n: Notifier) => Promise<NotifyRef | null>,
	opts: { rateLimit?: boolean } = { rateLimit: true },
): Promise<NotifyRef | null> {
	const notifier = getNotifier(env, cfg);
	if (!notifier) return null;
	if (opts.rateLimit !== false) {
		const { success } = await env.NOTIFY_LIMITER.limit({ key: "notify" });
		if (!success) {
			log("warn", "notify: rate limited, skipped", { label });
			return null;
		}
	}
	try {
		const ref = await send(notifier);
		log("info", "notify: sent", { label, channel: notifier.channel });
		return ref;
	} catch (err) {
		log("error", "notify: failed", { label, error: errorMessage(err) });
		return null;
	}
}

/**
 * Re-render the lead's posted message in place when there is one (its buttons stay), else
 * post one new message. A failed edit (for example a deleted message) also falls back to a
 * new message, so the update is never lost silently. Use inside `notifySafe`.
 */
export async function updateOrPostLead(n: Notifier, ref: NotifyRef | null, notice: LeadNotice): Promise<NotifyRef | null> {
	if (ref) {
		try {
			if (await n.updateLead(ref, notice)) return ref;
		} catch (err) {
			log("warn", "notify: lead update failed, posting a new message", { lead: notice.id, error: errorMessage(err) });
		}
	}
	return n.notifyLead(notice);
}

export async function resolveSafe(env: Env, cfg: Config, ref: NotifyRef | null, summary: string): Promise<void> {
	if (!ref) return;
	const notifier = getNotifier(env, cfg);
	if (!notifier) return;
	try {
		await notifier.resolve(ref, summary);
	} catch (err) {
		log("warn", "notify: resolve failed", { error: errorMessage(err) });
	}
}
