/**
 * Discord message builders (classic embeds + action-row buttons).
 * https://docs.discord.com/developers/components/reference
 *
 * custom_id format: "hp|<kind>|<action>|<arg>" (≤ 100 chars).
 * Untrusted values (hosts, URLs from beacons) are shown in inline code so they
 * never render as links or markdown; allowed_mentions is always empty.
 */
import type { CaseNotice, FlagNotice, LeadNotice } from "../types";

export type ActionKind = "lead" | "case" | "flag" | "test";

export interface ComponentAction {
	kind: ActionKind;
	action: string;
	arg: string;
}

const ORANGE = 0xf6821f;
const GREY = 0x6b7280;
const FOOTER = "cf-honeypot-html-identifier · human approval required";

export function encodeAction(kind: ActionKind, action: string, arg: string | number): string {
	return `hp|${kind}|${action}|${arg}`.slice(0, 100);
}

export function decodeAction(customId: string): ComponentAction | null {
	const m = /^hp\|(lead|case|flag|test)\|([a-z]+)\|(.+)$/.exec(customId);
	return m ? { kind: m[1] as ActionKind, action: m[2] ?? "", arg: m[3] ?? "" } : null;
}

const code = (v: string) => `\`${v.replace(/`/g, "'").slice(0, 900)}\``;
const button = (label: string, style: 1 | 2 | 3 | 4, customId: string) => ({ type: 2, style, label: label.slice(0, 80), custom_id: customId });
const link = (label: string, url: string) => ({ type: 2, style: 5, label: label.slice(0, 80), url: url.slice(0, 512) });
const row = (components: unknown[]) => ({ type: 1, components });

export interface DiscordPayload {
	content?: string;
	embeds: Record<string, unknown>[];
	components: unknown[];
	allowed_mentions: { parse: never[] };
}

function base(embed: Record<string, unknown>, components: unknown[]): DiscordPayload {
	return { embeds: [{ color: ORANGE, footer: { text: FOOTER }, ...embed }], components, allowed_mentions: { parse: [] } };
}

/**
 * What each lead source means, shown first so a weak signal isn't read as proof.
 * Canonical table: src/approvals/README.md#lead-sources
 */
const LEAD_SOURCE_TEXT: Record<string, string> = {
	beacon: "Our beacon script ran on a page on this host and reported a valid token: the page likely carries a copy of the site. ",
	referer:
		"Pages on this host load our images, scripts or stylesheets (foreign Referer). It may be a copy that hotlinks them, or a legitimate embed. ",
	brand_protection:
		"Brand Protection matched this host's name or a logo against one of your queries. That's a look-alike, **not proof of a copy**: check the page with `npm run hp -- decode <sample URL>` first. ",
};
const LEAD_SOURCE_FALLBACK = "A foreign host appears to run a copy of the site. ";

export function leadMessage(n: LeadNotice, interactive: boolean): DiscordPayload {
	const hint = `\nCLI: \`npm run hp -- approve-lead ${n.id}\` or \`npm run hp -- dismiss-lead ${n.id}\``;
	return base(
		{
			title: `${n.retryAfterCase ? "Investigation failed" : n.reopened ? "Re-scraped clone" : n.corroborated ? "Corroborated clone lead" : "Clone lead"}: ${n.host}`.slice(0, 256),
			description:
				(n.retryAfterCase
					? `Investigation ${code(n.retryAfterCase)} errored (see Workers Logs or \`npm run hp -- case-status ${n.retryAfterCase}\`), so the lead is pending again. `
					: "") +
				(n.reopened
					? "This host was already investigated, but a visitor's browser just reported a token that names a **new scraper IP**: the copy was refreshed from somewhere else. "
					: (LEAD_SOURCE_TEXT[n.source] ?? LEAD_SOURCE_FALLBACK)) +
				"**Investigate** starts one evidence Workflow (capture, decode, URL Scanner, Threat Intel). Nothing is enforced at this step." +
				(interactive ? "" : hint),
			fields: [
				...(n.corroborated
					? [
							{
								name: "Corroborated by beacon",
								value:
									`A page on this host reported one of our tokens${n.tokenRay ? ` (Ray ${code(n.tokenRay)})` : ""} after the lead was first seen. ` +
									"Still unconfirmed until **Investigate** finds it in the capture: a beacon report can be forged.",
							},
						]
					: []),
				{ name: "Source", value: n.source, inline: true },
				{ name: "Hits", value: String(n.hits), inline: true },
				{ name: "First seen", value: `<t:${n.firstSeen}:R>`, inline: true },
				{ name: "Sample URL", value: n.sampleUrl ? code(n.sampleUrl) : "n/a" },
				...(n.tokenRay && !n.corroborated ? [{ name: "Token Ray ID", value: code(n.tokenRay), inline: true }] : []),
			],
		},
		interactive ? [row([button("Investigate", 3, encodeAction("lead", "approve", n.id)), button("Dismiss", 2, encodeAction("lead", "dismiss", n.id))])] : [],
	);
}

export function caseMessage(n: CaseNotice, interactive: boolean): DiscordPayload {
	const lines = n.attribution.slice(0, 5).map(
		(a) =>
			`${code(a.ip)} · AS${a.asn}${a.org ? ` ${a.org}` : ""} · ${a.country} · score ${a.botScore ?? "n/a"} · ${a.fetchedAt.slice(0, 16)}Z` +
			(a.viaCloudflare ? ` · **Cloudflare IP: report, don't block**${a.cfWorkerZone ? ` (CF-Worker ${code(a.cfWorkerZone)})` : ""}` : "") +
			(a.verifiedBot ? " · **verified bot: never flagged**" : "") +
			(a.liveMirror ? " · live reverse proxy" : "") +
			(a.fromBeacon ? " · reported by beacon (unconfirmed)" : ""),
	);
	const hosting = !n.hostedOnCloudflare
		? "Not on Cloudflare: report to the hosting provider / registrar (see Threat Intel in the report)."
		: n.beaconOnly
			? "Proxied by / hosted on Cloudflare. **No abuse report draft**: the capture holds no token, so confirm the copy first (URL Scanner, a real browser)."
			: `Proxied by / hosted on Cloudflare: a **${n.abuseAct}** abuse report draft is in the evidence bundle.`;
	const hint = `\nCLI: \`npm run hp -- decide ${n.caseId} decoy|block|none\``;
	const decisionRow = row([
		// Labels say "case": the pending-flags digest has per-IP Decoy/Block buttons too.
		button("Decoy case IPs", 1, encodeAction("case", "decoy", n.caseId)),
		button("Block case IPs (WAF)", 4, encodeAction("case", "block", n.caseId)),
		button("Close case, no action", 2, encodeAction("case", "none", n.caseId)),
	]);
	const extra: unknown[] = [];
	if (n.abuseSubmitAvailable) extra.push(button(`Submit Cloudflare abuse report`, 4, encodeAction("case", "abuse", n.caseId)));
	if (n.scanReportUrl) extra.push(link("URL Scanner report", n.scanReportUrl));
	return base(
		{
			title: (n.beaconOnly ? `Case ${n.caseId}: unconfirmed copy on ${n.host} (beacon only)` : `Case ${n.caseId}: copy confirmed on ${n.host}`).slice(0, 256),
			description:
				(n.beaconOnly
					? `The capture of ${code(n.url)} holds **no token**, but a visitor's browser reported a valid one from this host. ` +
						"The copy may cloak the investigator, or the beacon report may be forged: verify the page before acting. No abuse draft was written.\n"
					: `${n.tokenCount} valid token(s) decoded from ${code(n.url)}\n`) +
				`SHA-256 \`${n.sha256.slice(0, 16)}…\`\n` +
				"Decide what happens to the IPs that fetched the copied HTML. Cloudflare IPs and verified bots are never flagged." +
				(interactive ? "" : hint),
			fields: [
				{ name: "Attribution (request that fetched the copy)", value: lines.join("\n").slice(0, 1024) || "n/a" },
				{ name: "Hosting", value: hosting },
			],
		},
		interactive ? [decisionRow, ...(extra.length ? [row(extra)] : [])] : n.scanReportUrl ? [row([link("URL Scanner report", n.scanReportUrl)])] : [],
	);
}

export function flagsMessage(flags: FlagNotice[], total: number, interactive: boolean): DiscordPayload {
	const shown = flags.slice(0, 5);
	return base(
		{
			title: `${total} pending trap flag(s)`,
			description:
				`Top ${shown.length} by hits. Nothing is enforced until approved; Cloudflare IPs and verified bots are never flagged.` +
				(interactive ? "" : "\nCLI: `npm run hp -- approve-flags <indicator>` or `npm run hp -- reject-flags <indicator>`"),
			fields: shown.map((f) => ({
				name: f.indicator.slice(0, 256),
				value: `${(f.reason ?? "trap hit").slice(0, 200)} · ${f.hits} hit(s) · <t:${f.createdAt}:R>`,
			})),
		},
		interactive
			? shown.map((f) =>
					row([
						button(`Decoy ${f.indicator.replace(/^ip:/, "")}`, 1, encodeAction("flag", "decoy", f.indicator)),
						button(`Block ${f.indicator.replace(/^ip:/, "")}`, 4, encodeAction("flag", "block", f.indicator)),
						button("Reject", 2, encodeAction("flag", "reject", f.indicator)),
					]),
				)
			: [],
	);
}

export function testMessage(interactive: boolean): DiscordPayload {
	return base(
		{
			title: "Honeypot notifications are working",
			description: interactive
				? "Click **Check access** to verify the Interactions Endpoint URL and whether you are an approver."
				: "Webhook (notify-only) mode: approvals happen via the admin CLI.",
		},
		interactive ? [row([button("Check access", 2, encodeAction("test", "ping", "0"))])] : [],
	);
}

interface MessageLike {
	embeds?: Record<string, unknown>[];
	components?: { type: number; components?: { custom_id?: string }[] }[];
}

export type RemoveMode = { type: "all" } | { type: "row"; customId: string } | { type: "button"; customId: string };

/**
 * Edit payload after an action: append a "Resolution" line and remove buttons:
 * all of them (lead/case decisions), the clicked row (digest: other flags stay
 * actionable) or only the clicked button (e.g. abuse report, decision still open).
 */
export function resolvedPayload(message: MessageLike | null, summary: string, remove: RemoveMode = { type: "all" }): Record<string, unknown> {
	const embed = { ...(message?.embeds?.[0] ?? {}) };
	const fields = Array.isArray(embed.fields) ? [...(embed.fields as { name: string; value: string }[])] : [];
	const existing = fields.find((f) => f.name === "Resolution");
	if (existing) existing.value = `${existing.value}\n${summary}`.slice(-1024);
	else fields.push({ name: "Resolution", value: summary.slice(0, 1024) });

	const rows = message?.components ?? [];
	let remaining: MessageLike["components"] = [];
	if (remove.type === "row") remaining = rows.filter((r) => !(r.components ?? []).some((c) => c.custom_id === remove.customId));
	if (remove.type === "button")
		remaining = rows
			.map((r) => ({ ...r, components: (r.components ?? []).filter((c) => c.custom_id !== remove.customId) }))
			.filter((r) => r.components.length > 0);
	const stillOpen = (remaining ?? []).some((r) => (r.components ?? []).some((c) => typeof c.custom_id === "string"));
	return {
		embeds: [{ ...embed, fields, color: stillOpen ? ORANGE : GREY }],
		components: remaining ?? [],
		allowed_mentions: { parse: [] },
	};
}
