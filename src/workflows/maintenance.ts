/**
 * MaintenanceWorkflow: runs daily via the Workflow `schedules` binding option
 * (and on demand via POST /__hp/maintenance/run).
 *
 *   expire flags: remove expired blocks from the WAF list FIRST, then delete the rows
 *   · reconcile the WAF list with active block flags (safety net)
 *   · purge stale leads
 *   · foreign-Referer hosts (WAE) → pending leads (one step per host)
 *   · Brand Protection string/logo matches → pending leads (recent only, capped, one step per host)
 *   · pending-flag digest (an IP that is also in an open case says so: decide it there)
 *
 * It never enforces anything new: it only creates PENDING leads for a human, and the
 * reconcile step only re-applies blocks a human already approved.
 */
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { cfApi, type BrandMatch } from "../integrations/cloudflare/api";
import { isCanonicalHost, loadConfig } from "../core/config";
import { reconcileWafList, removeBlocksFromWafDetailed, type WafRemoval } from "../approvals/enforce";
import { pendingFlagDigest } from "../approvals/digest";
import { recordLead } from "../approvals/leads";
import { notifySafe } from "../notify";
import { topForeignHosts } from "../storage/analytics";
import { deleteExpiredFlags, indicatorFor, listExpiredFlags, parseIndicator, purgeStaleLeads } from "../storage/d1";
import { errorMessage, hostMatchesSuffix, log, nowSec } from "../core/util";

const DAY = 86_400;
/** Only Brand Protection matches first seen this recently become leads. */
const BP_RECENT_DAYS = 2;
/** Hard cap on Brand Protection leads per run (one string query can have hundreds of matches). */
const BP_MAX_LEADS = 25;
/** Hard cap on foreign-Referer leads per run. */
const REFERER_MAX_LEADS = 50;
/** Expired flags handled per run; the rest wait for the next run. */
const EXPIRE_BATCH = 1000;
/** Bulk operations can queue behind each other; Workflow steps can afford to wait. */
const STEP_POLL_MS = 60_000;

function matchHost(m: BrandMatch): string | null {
	if (typeof m.domain === "string" && m.domain) return m.domain.toLowerCase();
	const u = typeof m.url === "string" ? m.url : null;
	try {
		return u ? new URL(u).hostname.toLowerCase() : null;
	} catch {
		return null;
	}
}

function isRecent(m: BrandMatch, since: number): boolean {
	const t = typeof m.first_seen === "string" ? Date.parse(m.first_seen) : Number.NaN;
	return Number.isFinite(t) ? t / 1000 >= since : true;
}

/** Step names must be unique and at most 256 characters; the index keeps them unique. */
const leadStepName = (kind: string, i: number, host: string) => `${kind} lead #${i + 1}: ${host}`.slice(0, 256);

export class MaintenanceWorkflow extends WorkflowEntrypoint<Env, unknown> {
	override async run(_event: Readonly<WorkflowEvent<unknown>>, step: WorkflowStep): Promise<unknown> {
		const env = this.env;
		const cfg = loadConfig(env);

		// 1. Expired flags. Read only; `now` is fixed here so later steps act on the same set.
		const expired = await step.do("find expired flags", async () => {
			const now = nowSec();
			const rows = await listExpiredFlags(env.DB, now, EXPIRE_BATCH);
			const blockIps = rows
				.filter((r) => r.action === "block" && r.status === "active" && r.kind === "ip")
				.map((r) => parseIndicator(r.indicator)?.value ?? "")
				.filter(Boolean);
			return { now, indicators: rows.map((r) => r.indicator), blockIps };
		});

		// 2. Remove their WAF list items BEFORE deleting the rows. Failures throw so the step
		//    retries; on the final attempt the per-IP result is returned instead, and the rows of
		//    IPs that still failed are kept so the next daily run retries them.
		let wafRemoval: WafRemoval = { status: "not_applicable", removed: [], failed: [] };
		if (expired.blockIps.length > 0) {
			wafRemoval = await step
				.do("remove expired WAF list items", { retries: { limit: 3, delay: "30 seconds", backoff: "exponential" } }, async (ctx) => {
					const r = await removeBlocksFromWafDetailed(env, cfg, expired.blockIps, { pollBudgetMs: STEP_POLL_MS, retryBudgetMs: STEP_POLL_MS });
					const finalAttempt = ctx.attempt > (ctx.config.retries?.limit ?? 0);
					if (r.failed.length > 0 && !finalAttempt) throw new Error(`waf removal failed for ${r.failed.length} ip(s): ${r.error ?? "unknown error"}`);
					return r;
				})
				.catch((err: unknown): WafRemoval => {
					log("error", "maintenance: waf removal step failed; keeping expired block rows", { error: errorMessage(err) });
					return { status: "error", removed: [], failed: expired.blockIps, error: errorMessage(err) };
				});
		}

		// 3. Delete the expired rows, except blocks whose list item could not be removed.
		const purged = await step.do("delete expired flags", async () => {
			const keep = new Set(wafRemoval.failed.map((ip) => indicatorFor("ip", ip)));
			const deletable = expired.indicators.filter((i) => !keep.has(i));
			return { deleted: await deleteExpiredFlags(env.DB, deletable, expired.now), kept: keep.size };
		});

		// 4. Safety net: list items without an active block flag are removed; missing active blocks are re-added.
		const reconcile = await step
			.do("reconcile WAF list", { retries: { limit: 2, delay: "1 minute", backoff: "exponential" }, timeout: "10 minutes" }, async () => {
				const r = await reconcileWafList(env, cfg, { pollBudgetMs: STEP_POLL_MS, retryBudgetMs: STEP_POLL_MS });
				return { status: r.status, listed: r.listed, truncated: r.truncated, removed: r.removed.length, added: r.added.length, waf: r.waf };
			})
			.catch((err: unknown) => `error: ${errorMessage(err)}`);

		const staleLeads = await step.do("purge stale leads", async () => purgeStaleLeads(env.DB, cfg.pendingTtlDays));

		// 5. Foreign Referers → leads, one step per host (a failure never re-runs other hosts' upserts or notifications).
		const refererHosts = await step.do("find foreign referer hosts", async () => {
			try {
				const hosts = await topForeignHosts(env, nowSec() - 2 * DAY);
				return hosts
					.map((h) => h.host)
					.filter((host) => !isCanonicalHost(cfg, host) && !hostMatchesSuffix(host, cfg.refererIgnore))
					.slice(0, REFERER_MAX_LEADS);
			} catch (err) {
				log("warn", "hotlink aggregation failed", { error: errorMessage(err) });
				return [];
			}
		});
		let hotlinkLeads = 0;
		for (const [i, host] of refererHosts.entries()) {
			const ok = await step
				.do(leadStepName("referer", i, host), { retries: { limit: 2, delay: "10 seconds", backoff: "exponential" } }, async () => {
					await recordLead(env, cfg, { host, sampleUrl: `https://${host}/`, source: "referer", tokenRay: null });
					return true;
				})
				.catch((err: unknown) => {
					log("error", "maintenance: referer lead failed", { host, error: errorMessage(err) });
					return false;
				});
			if (ok) hotlinkLeads++;
		}

		// 6. Brand Protection → leads: one step finds the hosts, then one step per host.
		const brandHosts = await step
			.do("find brand protection hosts", { retries: { limit: 2, delay: "30 seconds", backoff: "exponential" } }, async (): Promise<string[] | string> => {
				const api = cfApi(env);
				if (!api) return "skipped: CF_API_TOKEN not configured";
				const since = nowSec() - BP_RECENT_DAYS * DAY;
				const hosts = new Set<string>();
				const collect = (matches: BrandMatch[]) => {
					for (const m of matches) {
						const host = matchHost(m);
						if (host && isRecent(m, since) && !isCanonicalHost(cfg, host)) hosts.add(host);
					}
				};
				for (const q of await api.brandQueries()) {
					if (hosts.size >= BP_MAX_LEADS) break;
					collect(await api.brandMatches(q.query_id, BP_MAX_LEADS));
				}
				for (const logo of await api.brandLogos()) {
					if (hosts.size >= BP_MAX_LEADS) break;
					collect(await api.brandLogoMatches(logo.id, BP_MAX_LEADS));
				}
				return [...hosts].slice(0, BP_MAX_LEADS);
			})
			.catch((err: unknown) => `error: ${errorMessage(err)}`);
		let brandLeads: number | string = typeof brandHosts === "string" ? brandHosts : 0;
		if (Array.isArray(brandHosts)) {
			let n = 0;
			for (const [i, host] of brandHosts.entries()) {
				const ok = await step
					.do(leadStepName("brand", i, host), { retries: { limit: 2, delay: "10 seconds", backoff: "exponential" } }, async () => {
						await recordLead(env, cfg, { host, sampleUrl: `https://${host}/`, source: "brand_protection", tokenRay: null });
						return true;
					})
					.catch((err: unknown) => {
						log("error", "maintenance: brand protection lead failed", { host, error: errorMessage(err) });
						return false;
					});
				if (ok) n++;
			}
			brandLeads = n;
		}

		// One digest per run for trap flags (could be many): top 5 with per-flag buttons, each
		// annotated when an open case already covers its IP.
		const flagDigest = await step.do("pending flags digest", async () => {
			const { flags, total, inOpenCase } = await pendingFlagDigest(env.DB, 5);
			if (total === 0) return "none pending";
			const ref = await notifySafe(env, cfg, "flags", (n) => n.notifyFlags(flags, total), { rateLimit: false });
			const counts = `${total} pending${inOpenCase ? `, ${inOpenCase} also in an open case` : ""}`;
			return ref ? `sent (${counts})` : `not sent (${counts}; notifier disabled?)`;
		});

		const summary = {
			expiredFlags: expired.indicators.length,
			expiredBlockedIps: expired.blockIps.length,
			wafRemoval: { status: wafRemoval.status, removed: wafRemoval.removed.length, failed: wafRemoval.failed.length },
			purged,
			reconcile,
			staleLeads,
			hotlinkLeads,
			brandLeads,
			flagDigest,
		};
		log("info", "maintenance complete", summary);
		return summary;
	}
}
