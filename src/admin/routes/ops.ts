/** POST /notify/test · POST /notify/flags · POST /maintenance/run */
import { pendingFlagDigest } from "../../approvals/digest";
import { json, randomHex } from "../../core/util";
import { getNotifier, notifySafe } from "../../notify";
import type { AdminRoute } from "../context";

export const opsRoutes: AdminRoute = async ({ env, cfg, method, path }) => {
	if (method !== "POST") return null;

	if (path === "/notify/test") {
		const notifier = getNotifier(env, cfg);
		if (!notifier) {
			return json(
				{ ok: false, channel: cfg.notify.channel, error: "notifier not configured (see src/notify/README.md: bot token, channel id or webhook URL missing)" },
				{ status: 409 },
			);
		}
		const ref = await notifySafe(env, cfg, "test", (n) => n.test(), { rateLimit: false });
		return json({ ok: ref !== null, channel: notifier.channel, interactive: notifier.interactive, ref });
	}

	if (path === "/notify/flags") {
		const { flags, total, inOpenCase } = await pendingFlagDigest(env.DB, 5);
		if (total === 0) return json({ ok: true, sent: false, reason: "no pending flags" });
		const ref = await notifySafe(env, cfg, "flags", (n) => n.notifyFlags(flags, total), { rateLimit: false });
		return json({ ok: ref !== null, total, inOpenCase, ref });
	}

	if (path === "/maintenance/run") {
		const instance = await env.MAINTENANCE.create({ id: `maint-manual-${Date.now().toString(36)}-${randomHex(4)}` });
		return json({ ok: true, instance: instance.id }, { status: 202 });
	}
	return null;
};
