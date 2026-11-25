/**
 * Discord implementations of the Notifier interface:
 * - DiscordBotNotifier: bot token + channel → messages with approval buttons
 * - DiscordWebhookNotifier: channel webhook → notify-only (webhooks can't carry buttons)
 */
import type { CaseNotice, FlagNotice, LeadNotice, Notifier, NotifyRef } from "../types";
import { DiscordApi, executeWebhook } from "./api";
import { caseMessage, flagsMessage, leadMessage, resolvedPayload, testMessage, type DiscordPayload } from "./messages";

export function parseDiscordRef(ref: NotifyRef): { channelId: string; messageId: string } | null {
	const m = /^discord:(\d+):(\d+)$/.exec(ref);
	return m ? { channelId: m[1] ?? "", messageId: m[2] ?? "" } : null;
}

export class DiscordBotNotifier implements Notifier {
	readonly channel = "discord";
	readonly interactive = true;

	constructor(
		private readonly api: DiscordApi,
		private readonly channelId: string,
	) {}

	private async post(payload: DiscordPayload): Promise<NotifyRef> {
		const msg = await this.api.createMessage(this.channelId, payload);
		return `discord:${msg.channel_id}:${msg.id}`;
	}

	notifyLead(n: LeadNotice): Promise<NotifyRef> {
		return this.post(leadMessage(n, true));
	}

	notifyCase(n: CaseNotice): Promise<NotifyRef> {
		return this.post(caseMessage(n, true));
	}

	notifyFlags(flags: FlagNotice[], total: number): Promise<NotifyRef> {
		return this.post(flagsMessage(flags, total, true));
	}

	async resolve(ref: NotifyRef, summary: string): Promise<void> {
		const r = parseDiscordRef(ref);
		if (!r) return;
		// Without the original message body we can only replace the buttons with a note.
		await this.api.editMessage(r.channelId, r.messageId, { components: [], content: `Resolved: ${summary}`.slice(0, 2000), allowed_mentions: { parse: [] } });
	}

	test(): Promise<NotifyRef> {
		return this.post(testMessage(true));
	}
}

export class DiscordWebhookNotifier implements Notifier {
	readonly channel = "discord-webhook";
	readonly interactive = false;

	constructor(private readonly webhookUrl: string) {}

	private async post(payload: DiscordPayload): Promise<NotifyRef | null> {
		const msg = await executeWebhook(this.webhookUrl, payload);
		return msg ? `discord-webhook:${msg.channel_id}:${msg.id}` : null;
	}

	notifyLead(n: LeadNotice): Promise<NotifyRef | null> {
		return this.post(leadMessage(n, false));
	}

	notifyCase(n: CaseNotice): Promise<NotifyRef | null> {
		return this.post(caseMessage(n, false));
	}

	notifyFlags(flags: FlagNotice[], total: number): Promise<NotifyRef | null> {
		return this.post(flagsMessage(flags, total, false));
	}

	async resolve(): Promise<void> {
		// Notify-only channel: nothing to update.
	}

	test(): Promise<NotifyRef | null> {
		return this.post(testMessage(false));
	}
}

export { resolvedPayload };
