/**
 * Evidence report: report.json (machines) + report.md (the human reviewer),
 * stored next to the snapshot in R2 under cases/<caseId>/.
 */
import type { RayEnrichment } from "../storage/analytics";
import { isLiveMirror } from "./evidence";
import { isSkipped, type CaptureResult, type DecodeResult, type HostingSummary, type IntelSummary, type ScanSummary } from "./types";

export const caseKey = (caseId: string, file: string) => `cases/${caseId}/${file}`;
export const abuseReportKey = (caseId: string) => caseKey(caseId, "abuse-report-draft.json");

export interface ReportInput {
	caseId: string;
	url: string;
	host: string;
	capture: CaptureResult;
	decoded: DecodeResult;
	enrichment: Record<string, RayEnrichment | null>;
	scan: ScanSummary;
	intel: IntelSummary;
	hosting: HostingSummary | null;
}

/**
 * Untrusted text (the copy's URL, PTR names, AS organizations, registrars, User-Agents, DNS
 * answers) as literal Markdown: no links, raw HTML, table cells or emphasis. report.md is
 * served with a sandbox CSP, but a reviewer may paste it into a renderer that is not.
 */
export function escapeMd(value: unknown): string {
	return String(value ?? "")
		.replace(/[\r\n]+/g, " ")
		.replace(/[\\`*_{}[\]()<>#+!|~]/g, "\\$&");
}

/** Shorten for a table cell without cutting a word in half. */
export function shorten(value: string, max: number): string {
	if (value.length <= max) return value;
	const cut = value.slice(0, max - 1);
	const space = cut.lastIndexOf(" ");
	return `${(space > max * 0.6 ? cut.slice(0, space) : cut).trimEnd()}…`;
}

export function attributionRows(r: Pick<ReportInput, "decoded" | "enrichment">) {
	return r.decoded.tokens
		.map((t) => {
			const e = r.enrichment[t.fingerprint.rayId] ?? null;
			return {
				carrier: t.carrier,
				source: t.source,
				seconds_before_capture: Number.isFinite(t.secondsBeforeCapture) ? t.secondsBeforeCapture : null,
				live_mirror: isLiveMirror(t),
				ray_id: t.fingerprint.rayId,
				fetched_at: t.issuedAtIso,
				ip: t.fingerprint.ip,
				via_cloudflare: t.viaCloudflare,
				cf_worker_zone: e?.note || null,
				asn: t.fingerprint.asn,
				as_organization: e?.as_organization ?? null,
				country: t.fingerprint.country,
				colo: t.fingerprint.colo,
				bot_score: t.fingerprint.botScore,
				verified_bot: t.fingerprint.verifiedBot,
				user_agent: e?.user_agent ?? null,
				ja4: e?.ja4 ?? null,
				path_fetched: e?.path ?? null,
			};
		})
		.sort((a, b) => a.fetched_at.localeCompare(b.fetched_at));
}

export async function writeReport(env: Env, r: ReportInput): Promise<string> {
	const attribution = attributionRows(r);
	const onCf = r.hosting?.onCloudflare === true;
	const report = {
		case_id: r.caseId,
		generated_at: new Date().toISOString(),
		target: {
			url: r.url,
			final_url: r.capture.finalUrl,
			host: r.host,
			http_status: r.capture.status,
			bytes: r.capture.bytes,
			truncated: r.capture.truncated === true,
			sha256: r.capture.sha256,
			fetched_at: r.capture.fetchedAt,
			response_headers: r.capture.headers,
		},
		markers: {
			beacon_script: r.decoded.beaconScript,
			trap_link: r.decoded.trapLink,
			token_candidates: r.decoded.candidates,
			valid_tokens: r.decoded.tokens.length,
			omitted_tokens: r.decoded.omittedTokens ?? 0,
			beacon_only: r.decoded.beaconOnly === true,
			live_mirror: attribution.some((a) => a.live_mirror),
		},
		evidence_strength: r.decoded.beaconOnly
			? "unconfirmed: the capture holds no token; the token was reported by the beacon from a visitor's browser (possible cloaking or encoded token, or a forged beacon report)"
			: attribution.length > 0
				? "confirmed: the captured page contains our sealed token(s)"
				: "none",
		attribution,
		earliest_fetch: attribution[0] ?? null,
		cloudflare: {
			hosted_on_cloudflare: onCf,
			resolved_ips: r.hosting?.ips ?? [],
			abuse_report_draft: r.hosting?.abuseDraftKey ?? null,
			abuse_report_draft_skipped: r.hosting?.abuseDraftSkipped ?? null,
			scrapers_on_cloudflare: attribution.filter((a) => a.via_cloudflare).map((a) => ({ ip: a.ip, cf_worker_zone: a.cf_worker_zone })),
			guidance: !onCf
				? "The copy is not on Cloudflare: report it to its hosting provider (URL Scanner ASN) and registrar (WHOIS abuse contact)."
				: r.hosting?.abuseDraftKey
					? "The copy is proxied by / hosted on Cloudflare: submit an abuse report (https://abuse.cloudflare.com/) using the draft. Cloudflare forwards it to the host and site owner."
					: "The copy is proxied by / hosted on Cloudflare. No draft was written (see below): confirm the copy first, then report it at https://abuse.cloudflare.com/.",
		},
		url_scan: r.scan,
		intel: r.intel,
		evidence_files: {
			snapshot: r.capture.key,
			...(!isSkipped(r.scan) && r.scan.screenshotKey ? { screenshot: r.scan.screenshotKey } : {}),
			...(!isSkipped(r.intel) ? { intel: r.intel.key } : {}),
			...(r.hosting?.abuseDraftKey ? { abuse_report_draft: r.hosting.abuseDraftKey } : {}),
		},
		next_step:
			attribution.length > 0
				? `Approve in your notification channel, or POST /__hp/cases/${r.caseId}/decision {"action":"decoy"|"block"|"none"}`
				: "No valid token: this page cannot be attributed (paraphrased, stripped, or not a copy).",
		disclaimer:
			"Draft evidence for human review. A token names the request that fetched the copied HTML, not necessarily who published it (a scraper can present any genuine token it obtained). Cloudflare IPs and verified bots are never flagged. Not legal advice.",
	};

	const md = [
		`# Case ${r.caseId}`,
		"",
		`- **Suspected copy:** ${escapeMd(r.url)}`,
		`- **Captured:** ${r.capture.fetchedAt} · HTTP ${r.capture.status} · ${r.capture.bytes} bytes${r.capture.truncated ? " (truncated: only the first 2 MiB were captured and hashed)" : ""}`,
		`- **SHA-256 of capture:** \`${r.capture.sha256}\``,
		`- **Markers:** ${r.decoded.beaconOnly ? 0 : r.decoded.tokens.length} valid token(s) of ${r.decoded.candidates} candidate(s) in the capture${r.decoded.omittedTokens ? ` (${r.decoded.omittedTokens} more valid token(s) not recorded: at most ${r.decoded.tokens.length} per case)` : ""}; beacon script ${r.decoded.beaconScript ? "present" : "absent"}; trap link ${r.decoded.trapLink ? "present" : "absent"}`,
		`- **Evidence:** ${report.evidence_strength}`,
		...(r.decoded.beaconOnly
			? [
					"",
					"> **Unconfirmed copy.** The investigator's capture contains no token, but a visitor's browser running this host's page reported a valid one. Either the copy cloaks the investigator (CF-Worker header, Cloudflare ASN) or encodes the token, or someone posted a forged beacon report. Open the page in a real browser or check the URL Scanner screenshot before acting. The token still names who fetched the copied HTML.",
				]
			: []),
		...(report.markers.live_mirror
			? [
					"",
					"> **Live reverse proxy.** A token was issued seconds before the capture, i.e. by the capture itself: the copy fetches your page for every visitor. The IP below is the proxy's egress, not a one-off scrape.",
				]
			: []),
		"",
		"## Attribution (request that fetched the copied HTML)",
		"",
		attribution.length === 0
			? "_No valid token found._"
			: [
					"| Fetched at (UTC) | IP | ASN / Org | Country / Colo | Bot score | User-Agent | Ray ID |",
					"|---|---|---|---|---|---|---|",
					...attribution.map(
						(a) =>
							`| ${a.fetched_at} | ${a.ip}${a.via_cloudflare ? " (Cloudflare IP)" : ""}${a.verified_bot ? " (verified bot: never flagged)" : ""}${a.source === "beacon" ? " (via beacon)" : ""} | ${a.asn} ${escapeMd(a.as_organization ?? "")} | ${escapeMd(a.country)} / ${escapeMd(a.colo)} | ${a.bot_score ?? "n/a"} | ${escapeMd(shorten(a.user_agent ?? "n/a", 120))} | ${a.ray_id} |`,
					),
				].join("\n"),
		"",
		"## Cloudflare",
		"",
		r.hosting === null
			? "_Not checked (no valid token)._"
			: [
					`- Resolves to: ${escapeMd(r.hosting.ips.join(", ")) || "?"}${r.hosting.error ? ` (lookup error: ${escapeMd(r.hosting.error)})` : ""}`,
					`- ${report.cloudflare.guidance}`,
					...(r.hosting.abuseDraftKey ? [`- Abuse report draft: \`${r.hosting.abuseDraftKey}\` (review before submitting; nothing was sent)`] : []),
					...(r.hosting.abuseDraftSkipped ? [`- No abuse report draft: ${r.hosting.abuseDraftSkipped}`] : []),
					...report.cloudflare.scrapers_on_cloudflare.map(
						(s) => `- Scraper ${s.ip} is a Cloudflare IP${s.cf_worker_zone ? ` (CF-Worker: ${escapeMd(s.cf_worker_zone)})` : ""}: never blocked; include it in an abuse report.`,
					),
				].join("\n"),
		"",
		"## URL Scanner",
		"",
		isSkipped(r.scan)
			? `_Skipped: ${r.scan.skipped}_`
			: `- Report: ${escapeMd(r.scan.reportUrl ?? r.scan.uuid)}\n- Hosting: ${escapeMd(r.scan.pageIp ?? "?")} · AS${escapeMd(r.scan.pageAsn ?? "?")} · ${escapeMd(r.scan.pageCountry ?? "?")}\n- Malicious verdict: ${r.scan.verdictMalicious ?? "n/a"}`,
		"",
		"## Threat Intel",
		"",
		isSkipped(r.intel)
			? `_Skipped: ${r.intel.skipped}_`
			: [
					`- WHOIS domain: ${escapeMd(r.intel.whoisDomain ?? "not found")}`,
					`- Registrar: ${escapeMd(r.intel.registrar ?? "?")} (abuse contact: ${escapeMd(r.intel.registrarAbuseEmail ?? "?")})`,
					`- Domain created: ${escapeMd(r.intel.domainCreated ?? "?")}`,
					`- Nameservers: ${escapeMd(r.intel.nameservers.join(", ")) || "?"}`,
					...r.intel.ips.map((i) => `- Scraper IP ${i.ip}: AS${i.asn ?? "?"} ${escapeMd(i.org ?? "")} (${escapeMd(i.type ?? "?")}), PTR ${escapeMd(i.ptr ?? "n/a")}`),
					...(r.intel.errors.length ? [`- Lookup errors: ${escapeMd(r.intel.errors.join("; "))}`] : []),
				].join("\n"),
		"",
		"## Next step (human decision required)",
		"",
		report.next_step,
		"",
		`> ${report.disclaimer}`,
		"",
	].join("\n");

	const key = caseKey(r.caseId, "report.json");
	await env.EVIDENCE.put(key, JSON.stringify(report, null, 2), { httpMetadata: { contentType: "application/json" } });
	await env.EVIDENCE.put(caseKey(r.caseId, "report.md"), md, { httpMetadata: { contentType: "text/markdown" } });
	return key;
}
