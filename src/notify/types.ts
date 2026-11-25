/**
 * Channel-agnostic human-in-the-loop notifications.
 *
 * A Notifier posts approval requests (new lead, case awaiting decision,
 * pending trap flags) to a chat channel. Interactive channels (Discord bot,
 * and in future Slack apps or Telegram bots) render buttons that call back
 * into src/approvals/actions.ts; notify-only channels (webhooks) include the
 * equivalent CLI commands instead.
 */

/** Channel-specific message reference, e.g. "discord:<channelId>:<messageId>". */
export type NotifyRef = string;

export interface LeadNotice {
	id: number;
	host: string;
	source: string;
	sampleUrl: string | null;
	tokenRay: string | null;
	firstSeen: number;
	hits: number;
	/** True when an already-investigated host was re-scraped from a new IP and the lead re-opened. */
	reopened?: boolean;
}

export interface AttributionLine {
	ip: string;
	asn: number;
	org: string | null;
	country: string;
	botScore: number | null;
	fetchedAt: string;
	rayId: string;
	viaCloudflare: boolean;
	/** The token says the fetch was a verified bot: never flagged. */
	verifiedBot?: boolean;
	/** Token reported by the beacon (the capture found none): unconfirmed. */
	fromBeacon?: boolean;
	/** Token minted during the capture: the copy is a live reverse proxy. */
	liveMirror?: boolean;
	/** CF-Worker zone of the fetch (scraper running in a Cloudflare Worker). */
	cfWorkerZone?: string | null;
}

export interface CaseNotice {
	caseId: string;
	url: string;
	host: string;
	sha256: string;
	tokenCount: number;
	attribution: AttributionLine[];
	/** The capture held no token; the only evidence is the lead's beacon token (possible cloaking). */
	beaconOnly?: boolean;
	hostedOnCloudflare: boolean;
	scanReportUrl: string | null;
	/** True when a Cloudflare abuse report can be submitted from the message (ABUSE_REPORTS=submit). */
	abuseSubmitAvailable: boolean;
	abuseAct: string;
}

export interface FlagNotice {
	indicator: string;
	reason: string | null;
	hits: number;
	createdAt: number;
}

export interface Notifier {
	readonly channel: string;
	/** Whether the channel can receive button clicks (otherwise CLI hints are shown). */
	readonly interactive: boolean;
	notifyLead(n: LeadNotice): Promise<NotifyRef | null>;
	notifyCase(n: CaseNotice): Promise<NotifyRef | null>;
	notifyFlags(flags: FlagNotice[], totalPending: number): Promise<NotifyRef | null>;
	/** Mark a previously posted request as handled (e.g. approved from the admin API). */
	resolve(ref: NotifyRef, summary: string): Promise<void>;
	test(): Promise<NotifyRef | null>;
}
