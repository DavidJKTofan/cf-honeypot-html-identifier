/**
 * InvestigateWorkflow: one durable instance per approved lead / manual case.
 *
 *   capture (browser-like UA) → R2 snapshot + SHA-256 → decode tokens (+ Cloudflare-IP check)
 *   → [no token in capture] fall back to the lead's beacon token (unconfirmed, labelled)
 *   → [fresh token, e.g. live proxy] wait for Analytics Engine ingestion → WAE enrichment
 *   → [token found] Cloudflare hosting check (DoH) → abuse report draft if on Cloudflare
 *     (never for beacon-only evidence)
 *   → URL Scanner (Unlisted) + Threat Intel (quota-capped, best-effort)
 *   → report.json + report.md in R2 → notify reviewers (Discord buttons, …)
 *   → WAIT for a human decision (7 days) → apply decoy / block / none → close
 *
 * Nothing is enforced and no report is submitted automatically, and Cloudflare
 * IPs and verified bots are never flagged. https://developers.cloudflare.com/workflows/
 */
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { decodeTokens, fetchPage, type DecodedToken } from "../admin/decode";
import { DECISION_EVENT, type Decision, type InvestigateParams } from "../approvals/cases";
import { downgradedBlockIp, recordApprovedFlag, removeBlocksFromWaf, syncBlocksToWaf } from "../approvals/enforce";
import { notifyLead } from "../approvals/leads";
import { loadConfig } from "../core/config";
import { errorMessage, log } from "../core/util";
import { scanHtml } from "../identity/carriers";
import type { Fingerprint } from "../identity/fingerprint";
import { draftAbuseReport } from "../integrations/cloudflare/abuse";
import { cfApi } from "../integrations/cloudflare/api";
import { checkCloudflareHosting, isCloudflareIp, loadCloudflareRanges } from "../integrations/cloudflare/ip-ranges";
import { notifySafe } from "../notify";
import { lookupRay, type RayEnrichment } from "../storage/analytics";
import { getCase, getLead, insertCaseTokens, releaseLead, setCaseStatusIf, updateCase, type FlagRow, type LeadRow } from "../storage/d1";
import { capCaseTokens, decisionTargets, isLiveMirror, needsIngestionWait, secondsBeforeCapture } from "./evidence";
import { abuseReportKey, attributionRows, caseKey, writeReport } from "./report";
import {
	get,
	isSkipped,
	str,
	type AppliedDecision,
	type CaptureResult,
	type DecodeResult,
	type HostingSummary,
	type IntelSummary,
	type IpIntel,
	type ScanSummary,
	type Skipped,
	type TokenEvidence,
} from "./types";

/** host, then parent domains (WHOIS is omitted for subdomains), at most 3 lookups. */
function whoisCandidates(host: string): string[] {
	const labels = host.split(".");
	const out: string[] = [];
	for (let i = 0; i <= labels.length - 2 && out.length < 3; i++) out.push(labels.slice(i).join("."));
	return out;
}

const skip = (reason: string) => (err: unknown): Skipped => ({ skipped: `${reason}: ${errorMessage(err)}` });

export class InvestigateWorkflow extends WorkflowEntrypoint<Env, InvestigateParams> {
	override async run(event: Readonly<WorkflowEvent<InvestigateParams>>, step: WorkflowStep): Promise<unknown> {
		const env = this.env;
		const cfg = loadConfig(env);
		const { caseId, url, host } = event.payload;
		const leadId = event.payload.leadId ?? null;

		try {
			const capture = await step.do(
				"capture suspected copy",
				{ retries: { limit: 3, delay: "15 seconds", backoff: "exponential" }, timeout: "2 minutes" },
				async (): Promise<CaptureResult> => {
					const page = await fetchPage(url, undefined, undefined, cfg.captureUserAgent);
					const key = caseKey(caseId, "snapshot.html");
					await env.EVIDENCE.put(key, page.bytes, {
						httpMetadata: { contentType: page.contentType || "text/html" },
						customMetadata: { sha256: page.sha256, url, finalUrl: page.finalUrl, status: String(page.status), fetchedAt: page.fetchedAt, truncated: String(page.truncated) },
					});
					return { key, sha256: page.sha256, status: page.status, finalUrl: page.finalUrl, bytes: page.bytes.byteLength, truncated: page.truncated, fetchedAt: page.fetchedAt, headers: page.headers };
				},
			);

			const decoded = await step.do("extract and open tokens", async (): Promise<DecodeResult> => {
				const obj = await env.EVIDENCE.get(capture.key);
				const scan = await scanHtml(obj ? await obj.text() : "", cfg);
				const ranges = await loadCloudflareRanges();
				const evidence = (found: DecodedToken[], source: TokenEvidence["source"]): TokenEvidence[] =>
					found
						.filter((t): t is DecodedToken & { fingerprint: Fingerprint; issuedAtIso: string } => t.valid && !!t.fingerprint && !!t.issuedAtIso)
						.map((t) => ({
							carrier: t.carrier,
							issuedAtIso: t.issuedAtIso,
							fingerprint: t.fingerprint,
							viaCloudflare: isCloudflareIp(t.fingerprint.ip, ranges),
							source,
							secondsBeforeCapture: secondsBeforeCapture(t.fingerprint.issuedAt, capture.fetchedAt),
						}));
				// Bounded: a page stuffed with genuine tokens can't push this step past its 1 MiB result.
				const capped = capCaseTokens(evidence(await decodeTokens(env, scan.tokens, { enrich: false }), "capture"));
				const tokens = [...capped.kept];
				// The capture found nothing, but a visitor's browser reported a valid token from this
				// host (the lead's beacon token): the copy may cloak the investigator (CF-Worker header,
				// Cloudflare ASN) or encode the token. Use it as UNCONFIRMED evidence, labelled as such.
				// Only for the lead's own host: the token says nothing about any other site.
				let beaconOnly = false;
				if (tokens.length === 0 && leadId !== null) {
					const lead = await getLead(env.DB, leadId);
					if (lead?.token && lead.host === host) {
						const reported = evidence(await decodeTokens(env, [{ carrier: "beacon", token: lead.token }], { enrich: false }), "beacon");
						tokens.push(...reported);
						beaconOnly = reported.length > 0;
					}
				}
				return {
					beaconScript: scan.beaconScript,
					trapLink: scan.trapLink,
					candidates: scan.tokens.length,
					tokens,
					beaconOnly,
					...(capped.omitted > 0 ? { omittedTokens: capped.omitted } : {}),
				};
			});

			// A live reverse proxy mints its token during our own capture; its Analytics Engine row
			// (User-Agent, JA4, CF-Worker zone) takes up to a minute to become queryable.
			if (needsIngestionWait(decoded.tokens)) await step.sleep("wait for analytics ingestion", "90 seconds");

			const enrichment = await step.do("enrich from analytics engine", async (): Promise<Record<string, RayEnrichment | null>> => {
				const out: Record<string, RayEnrichment | null> = {};
				for (const t of decoded.tokens.slice(0, 20)) {
					try {
						out[t.fingerprint.rayId] = await lookupRay(env, t.fingerprint.rayId, t.fingerprint.issuedAt);
					} catch (err) {
						log("warn", "enrichment failed", { caseId, error: errorMessage(err) });
						out[t.fingerprint.rayId] = null;
					}
				}
				return out;
			});

			await step.do("record decoded tokens", async () => {
				await insertCaseTokens(
					env.DB,
					decoded.tokens.map((t) => ({
						case_id: caseId,
						ray_id: t.fingerprint.rayId,
						ip: t.fingerprint.ip,
						asn: t.fingerprint.asn,
						country: t.fingerprint.country,
						issued_at: t.fingerprint.issuedAt,
						carrier: t.carrier,
					})),
				);
				await updateCase(env.DB, caseId, { token_count: decoded.tokens.length });
			});

			if (decoded.tokens.length === 0) {
				await step.do("close: no attributable token", async () => {
					const none = { skipped: "no token found" };
					const key = await writeReport(env, { caseId, url, host, capture, decoded, enrichment, scan: none, intel: none, hosting: null });
					await updateCase(env.DB, caseId, { status: "no_evidence", report_key: key });
				});
				return { caseId, status: "no_evidence" };
			}

			// Free and quota-less: does the copy resolve to Cloudflare? Then the right channel is a Cloudflare abuse report.
			const hosting = await step.do("cloudflare hosting check", { retries: { limit: 2, delay: "5 seconds", backoff: "constant" } }, async (): Promise<HostingSummary> => {
				const check = await checkCloudflareHosting(host, await loadCloudflareRanges());
				let abuseDraftKey: string | null = null;
				let abuseDraftSkipped: string | null = null;
				if (check.onCloudflare && decoded.beaconOnly) {
					// An abuse report states that the page contains our identifier; with beacon-only
					// evidence the capture can't show that (and a beacon report can be forged).
					abuseDraftSkipped =
						"beacon-only evidence: the capture holds no token, so it can't show the page contains our identifier. Verify the copy (URL Scanner screenshot, a real browser) before reporting.";
				} else if (check.onCloudflare) {
					const workerZones = [
						...new Set(decoded.tokens.filter((t) => t.viaCloudflare).map((t) => enrichment[t.fingerprint.rayId]?.note ?? "").filter(Boolean)),
					];
					const draft = draftAbuseReport({
						act: cfg.abuse.act,
						caseId,
						cloneUrls: [capture.finalUrl || url],
						originalUrl: `${cfg.siteOrigin}${enrichment[decoded.tokens[0]?.fingerprint.rayId ?? ""]?.path ?? "/"}`,
						sha256: capture.sha256,
						capturedAt: capture.fetchedAt,
						rayIds: decoded.tokens.map((t) => t.fingerprint.rayId),
						workerZones,
						liveMirror: decoded.tokens.some(isLiveMirror),
					});
					abuseDraftKey = abuseReportKey(caseId);
					await env.EVIDENCE.put(abuseDraftKey, JSON.stringify(draft, null, 2), { httpMetadata: { contentType: "application/json" } });
				}
				await updateCase(env.DB, caseId, { hosted_on_cloudflare: check.onCloudflare ? 1 : 0 });
				return { ips: check.ips, onCloudflare: check.onCloudflare, error: check.error ?? null, abuseDraftKey, abuseDraftSkipped };
			});

			// Quota-consuming lookups only run once a copy is proven (valid token). Best-effort.
			const submitted = await step
				.do("submit url scan", { retries: { limit: 2, delay: "10 seconds", backoff: "exponential" } }, async (): Promise<Skipped | { uuid: string; reportUrl: string | null }> => {
					const api = cfApi(env);
					if (!api) return { skipped: "CF_API_TOKEN not configured" };
					const r = await api.urlscanSubmit(capture.finalUrl || url, cfg.urlscanVisibility);
					return { uuid: r.uuid, reportUrl: r.result ?? null };
				})
				.catch(skip("url scan submit failed"));

			let scan: ScanSummary = isSkipped(submitted) ? submitted : { skipped: "url scan pending" };
			if (!isSkipped(submitted)) {
				await step.sleep("let the url scan run", "45 seconds");
				scan = await step
					.do("collect url scan result", { retries: { limit: 10, delay: "20 seconds", backoff: "constant" }, timeout: "1 minute" }, async (): Promise<ScanSummary> => {
						const api = cfApi(env);
						if (!api) return { skipped: "CF_API_TOKEN not configured" };
						const res = await api.urlscanResult(submitted.uuid);
						if (!res) throw new Error("url scan not finished yet");
						await env.EVIDENCE.put(caseKey(caseId, "urlscan.json"), JSON.stringify(res, null, 2), { httpMetadata: { contentType: "application/json" } });
						const shot = await api.urlscanScreenshot(submitted.uuid);
						const screenshotKey = shot ? caseKey(caseId, "screenshot.png") : null;
						if (shot && screenshotKey) await env.EVIDENCE.put(screenshotKey, shot, { httpMetadata: { contentType: "image/png" } });
						const malicious = get(res, "verdicts", "overall", "malicious");
						const asn = get(res, "page", "asn");
						return {
							uuid: submitted.uuid,
							reportUrl: submitted.reportUrl,
							verdictMalicious: typeof malicious === "boolean" ? malicious : null,
							pageUrl: str(get(res, "page", "url")),
							pageIp: str(get(res, "page", "ip")),
							pageAsn: str(asn) ?? (typeof asn === "number" ? String(asn) : null),
							pageCountry: str(get(res, "page", "country")),
							screenshotKey,
						};
					})
					.catch(skip("url scan result unavailable"));
			}

			const intel = await step
				.do("threat intel lookups", { retries: { limit: 2, delay: "10 seconds", backoff: "exponential" } }, async (): Promise<IntelSummary> => {
					const api = cfApi(env);
					if (!api) return { skipped: "CF_API_TOKEN not configured" };
					const errors: string[] = [];
					const attempt = async (label: string, fn: () => Promise<unknown>) => {
						try {
							return await fn();
						} catch (err) {
							errors.push(`${label}: ${errorMessage(err)}`);
							return null;
						}
					};
					let whois: unknown = null;
					let whoisDomain: string | null = null;
					for (const candidate of whoisCandidates(host)) {
						const w = await attempt(`whois ${candidate}`, () => api.intelWhois(candidate));
						if (w && typeof w === "object" && (get(w, "found") === true || str(get(w, "registrar")))) {
							whois = w;
							whoisDomain = candidate;
							break;
						}
					}
					const ips = [...new Set(decoded.tokens.map((t) => t.fingerprint.ip))].slice(0, cfg.intelMaxIpsPerCase);
					const full = {
						domain: await attempt("domain", () => api.intelDomain(host)),
						whois,
						whoisDomain,
						ips: Object.fromEntries(await Promise.all(ips.map(async (ip) => [ip, await attempt(`ip ${ip}`, () => api.intelIp(ip))]))),
					};
					const key = caseKey(caseId, "intel.json");
					await env.EVIDENCE.put(key, JSON.stringify(full, null, 2), { httpMetadata: { contentType: "application/json" } });
					const ns = get(full.whois, "nameservers");
					const ipIntel: IpIntel[] = ips.map((ip) => {
						const raw = full.ips[ip];
						const entry = Array.isArray(raw) ? raw[0] : raw;
						const ptr = get(entry, "ptr_lookup", "ptr_domains");
						const asn = get(entry, "belongs_to_ref", "value");
						return {
							ip,
							asn: typeof asn === "number" ? asn : null,
							org: str(get(entry, "belongs_to_ref", "description")),
							type: str(get(entry, "belongs_to_ref", "type")),
							ptr: Array.isArray(ptr) && typeof ptr[0] === "string" ? ptr[0] : null,
						};
					});
					return {
						key,
						whoisDomain,
						registrar: str(get(full.whois, "registrar")) ?? str(get(full.whois, "registrar_name")),
						registrarAbuseEmail: str(get(full.whois, "registrar_email")),
						domainCreated: str(get(full.whois, "created_date")),
						nameservers: Array.isArray(ns) ? ns.filter((x): x is string => typeof x === "string").slice(0, 10) : [],
						ips: ipIntel,
						errors,
					};
				})
				.catch(skip("intel lookups failed"));

			await step.do("write evidence report", async () => {
				const key = await writeReport(env, { caseId, url, host, capture, decoded, enrichment, scan, intel, hosting });
				await updateCase(env.DB, caseId, { status: "awaiting_decision", report_key: key });
				log("info", "case awaiting human decision", { caseId, host, tokens: decoded.tokens.length });
			});

			// Two steps so a failed D1 write is retried on its own and never re-posts the message.
			const notifyRef = await step.do("notify reviewers", async (): Promise<string | null> => {
				// An earlier run may already have saved a ref (for example after a manual restart).
				const existing = (await getCase(env.DB, caseId))?.notify_ref;
				if (existing) return existing;
				const rows = attributionRows({ decoded, enrichment });
				return notifySafe(
					env,
					cfg,
					"case",
					(n) =>
						n.notifyCase({
							caseId,
							url,
							host,
							sha256: capture.sha256,
							tokenCount: decoded.tokens.length,
							attribution: rows.map((a) => ({
								ip: a.ip,
								asn: a.asn,
								org: a.as_organization,
								country: a.country,
								botScore: a.bot_score,
								fetchedAt: a.fetched_at,
								rayId: a.ray_id,
								viaCloudflare: a.via_cloudflare,
								verifiedBot: a.verified_bot,
								fromBeacon: a.source === "beacon",
								liveMirror: a.live_mirror,
								cfWorkerZone: a.cf_worker_zone,
							})),
							beaconOnly: decoded.beaconOnly === true,
							hostedOnCloudflare: hosting.onCloudflare,
							scanReportUrl: isSkipped(scan) ? null : scan.reportUrl,
							abuseSubmitAvailable: hosting.abuseDraftKey !== null && cfg.abuse.mode === "submit",
							abuseAct: cfg.abuse.act,
						}),
					{ rateLimit: false },
				);
			});
			if (notifyRef) {
				await step.do("save notification ref", async () => {
					await updateCase(env.DB, caseId, { notify_ref: notifyRef });
				});
			}

			let decision: Decision;
			try {
				const ev = await step.waitForEvent<Decision>("wait for human decision", { type: DECISION_EVENT, timeout: "7 days" });
				decision = ev.payload;
			} catch {
				// Conditional, like every claim: a click that lands as the wait times out may already
				// have claimed the case (`applying`) and sent its event to this instance.
				const expiry = await step.do("expire undecided case", async () => setCaseStatusIf(env.DB, caseId, ["awaiting_decision"], "expired"));
				if (expiry.changed || expiry.status !== "applying") return { caseId, status: expiry.status ?? "expired" };
				// That late decision was claimed and told "delivered". Its event is buffered for this
				// instance, so pick it up here and apply it instead of overwriting the case as expired.
				try {
					const late = await step.waitForEvent<Decision>("wait for late decision", { type: DECISION_EVENT, timeout: "10 minutes" });
					decision = late.payload;
				} catch {
					// The claim never produced an event (its sendEvent failed and the claim was released).
					const end = await step.do("expire after late claim", async () => setCaseStatusIf(env.DB, caseId, ["awaiting_decision", "applying"], "expired"));
					return { caseId, status: end.status ?? "expired" };
				}
			}

			// D1 flags first (idempotent upserts), then ONE WAF list write for every block in its own
			// step: one bulk operation per decision instead of one per IP, so writes never collide.
			const {
				applied: decided,
				rows,
				downgraded,
			} = await step.do("apply human decision", async (): Promise<{ applied: AppliedDecision; rows: FlagRow[]; downgraded: string[] }> => {
				const ttlDays = decision.ttlDays ?? cfg.flagTtlDays;
				const ranges = await loadCloudflareRanges();
				const targets = decisionTargets(decoded.tokens, decision.ips, ranges);
				const result: AppliedDecision = {
					action: decision.action,
					indicators: [],
					skippedCloudflareIps: targets.skippedCloudflareIps,
					skippedVerifiedBotIps: targets.skippedVerifiedBotIps,
					waf: [],
					ttlDays,
					note: decision.note ?? null,
					actor: decision.actor ?? null,
				};
				if (decision.action === "none") return { applied: result, rows: [], downgraded: [] };
				const flagRows: FlagRow[] = [];
				// Active blocks this decision turns into decoys: their WAF list items must go too.
				const downgradedIps: string[] = [];
				for (const ip of targets.act) {
					const approved = await recordApprovedFlag(
						env,
						{
							kind: "ip",
							value: ip,
							action: decision.action,
							reason: `case ${caseId}: copy found on ${host}`,
							source: "case",
							sourceRef: caseId,
							ttlDays,
						},
						ranges,
					);
					flagRows.push(approved.row);
					result.indicators.push(approved.row.indicator);
					const downgradedIp = downgradedBlockIp(approved);
					if (downgradedIp) downgradedIps.push(downgradedIp);
				}
				return { applied: result, rows: flagRows, downgraded: downgradedIps };
			});

			let waf: string = "not_applicable";
			if (decided.action === "block" && rows.length > 0) {
				// Throws on failure so the retries apply; a final failure is recorded, not fatal.
				// The Worker's 403 fallback still blocks these IPs, and daily maintenance re-adds them.
				waf = await step
					.do("sync WAF list", { retries: { limit: 3, delay: "20 seconds", backoff: "exponential" }, timeout: "5 minutes" }, async () =>
						syncBlocksToWaf(env, cfg, rows, { throwOnError: true, pollBudgetMs: 60_000, retryBudgetMs: 60_000 }),
					)
					.catch((err: unknown) => {
						log("error", "case: waf list sync failed", { caseId, error: errorMessage(err) });
						return "error";
					});
			} else if (decided.action === "decoy" && downgraded.length > 0) {
				// A decoy for an IP that was blocked: without this, the edge keeps blocking it (the list
				// rule runs before the Worker) and the decoy never shows. Reconcile is the daily backstop.
				waf = await step
					.do("remove downgraded blocks from WAF list", { retries: { limit: 3, delay: "20 seconds", backoff: "exponential" }, timeout: "5 minutes" }, async () =>
						removeBlocksFromWaf(env, cfg, downgraded, { throwOnError: true, pollBudgetMs: 60_000, retryBudgetMs: 60_000 }),
					)
					.catch((err: unknown) => {
						log("error", "case: waf list removal failed", { caseId, error: errorMessage(err) });
						return "error";
					});
			}
			const applied: AppliedDecision = { ...decided, waf: [waf] };

			await step.do("close case", async () => {
				const body = JSON.stringify({ decidedAt: new Date().toISOString(), decision, applied }, null, 2);
				await env.EVIDENCE.put(caseKey(caseId, "decision.json"), body, { httpMetadata: { contentType: "application/json" } });
				// Conditional: never overwrite a status this Workflow did not expect. `awaiting_decision`
				// covers an event sent without a claim (for example the Workflows REST API).
				const r = await setCaseStatusIf(env.DB, caseId, ["applying", "awaiting_decision"], "closed", {
					decision: JSON.stringify(applied),
					decided_by: applied.actor,
				});
				if (!r.changed) log("warn", "case: close skipped, unexpected status", { caseId, status: r.status });
			});
			return { caseId, status: "closed", applied };
		} catch (err) {
			await step.do("mark case errored", async () => {
				await updateCase(env.DB, caseId, { status: "errored" });
			});
			if (leadId !== null) await this.reofferLead(step, caseId, leadId);
			throw err;
		}
	}

	/**
	 * An errored investigation must not strand its lead as `approved` (no buttons, no way to
	 * approve it again): put it back to `pending` and offer it again. Best-effort: never masks
	 * the original error.
	 */
	private async reofferLead(step: WorkflowStep, caseId: string, leadId: number): Promise<void> {
		const env = this.env;
		try {
			const lead = await step.do("release lead after error", async (): Promise<LeadRow | null> => {
				if (!(await releaseLead(env.DB, leadId, caseId))) return null;
				return getLead(env.DB, leadId);
			});
			if (!lead) return;
			await step.do("offer lead again after error", async () => {
				// A one-off per errored case, not public-traffic driven: not rate-limited.
				await notifyLead(env, loadConfig(env), lead, false, { rateLimit: false, retryAfterCase: caseId });
			});
		} catch (err) {
			log("error", "case: could not release the lead after an error", { caseId, leadId, error: errorMessage(err) });
		}
	}
}
