/**
 * Minimal Discord REST client (bot token + interaction webhooks).
 * https://docs.discord.com/developers/reference
 */
import { errorMessage, log } from "../../core/util";

const USER_AGENT = "DiscordBot (https://github.com/DavidJKTofan/cf-honeypot-html-identifier, 0.1.0)";

export class DiscordApiError extends Error {
	constructor(
		message: string,
		readonly status: number,
	) {
		super(message);
	}
}

export interface DiscordMessage {
	id: string;
	channel_id: string;
}

export class DiscordApi {
	constructor(
		private readonly base: string,
		private readonly botToken: string | null,
	) {}

	private async call<T>(method: string, path: string, body: unknown, auth: boolean): Promise<T> {
		for (let attempt = 0; attempt < 2; attempt++) {
			const res = await fetch(`${this.base}${path}`, {
				method,
				headers: {
					"content-type": "application/json",
					"user-agent": USER_AGENT,
					...(auth && this.botToken ? { authorization: `Bot ${this.botToken}` } : {}),
				},
				body: JSON.stringify(body),
				signal: AbortSignal.timeout(8_000),
			});
			if (res.status === 429 && attempt === 0) {
				const retry = Number(res.headers.get("retry-after") ?? "1");
				if (retry <= 5) {
					await scheduler.wait(Math.ceil(retry * 1000));
					continue;
				}
			}
			const text = await res.text();
			if (!res.ok) throw new DiscordApiError(`Discord ${method} ${path} → ${res.status} ${text.slice(0, 300)}`, res.status);
			return (text ? JSON.parse(text) : null) as T;
		}
		throw new DiscordApiError(`Discord ${method} ${path} → rate limited`, 429);
	}

	createMessage(channelId: string, body: unknown): Promise<DiscordMessage> {
		return this.call("POST", `/channels/${channelId}/messages`, body, true);
	}

	editMessage(channelId: string, messageId: string, body: unknown): Promise<DiscordMessage> {
		return this.call("PATCH", `/channels/${channelId}/messages/${messageId}`, body, true);
	}

	/** Edit the message an interaction came from (works for 15 min; no bot token needed). */
	async editOriginal(applicationId: string, interactionToken: string, body: unknown): Promise<void> {
		try {
			await this.call("PATCH", `/webhooks/${applicationId}/${interactionToken}/messages/@original`, body, false);
		} catch (err) {
			log("error", "discord: edit original failed", { error: errorMessage(err) });
		}
	}

	/** Ephemeral follow-up visible only to the clicking user. */
	async followup(applicationId: string, interactionToken: string, content: string): Promise<void> {
		try {
			await this.call("POST", `/webhooks/${applicationId}/${interactionToken}`, { content, flags: 64, allowed_mentions: { parse: [] } }, false);
		} catch (err) {
			log("error", "discord: followup failed", { error: errorMessage(err) });
		}
	}
}

/** Execute a plain channel webhook (notify-only: these cannot carry interactive buttons). */
export async function executeWebhook(webhookUrl: string, body: unknown): Promise<DiscordMessage | null> {
	const url = new URL(webhookUrl);
	url.searchParams.set("wait", "true");
	const res = await fetch(url, {
		method: "POST",
		headers: { "content-type": "application/json", "user-agent": USER_AGENT },
		body: JSON.stringify(body),
		signal: AbortSignal.timeout(8_000),
	});
	if (!res.ok) throw new DiscordApiError(`Discord webhook → ${res.status} ${(await res.text()).slice(0, 300)}`, res.status);
	return (await res.json()) as DiscordMessage;
}
