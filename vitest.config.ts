import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
	plugins: [
		cloudflareTest(async () => ({
			wrangler: { configPath: "./wrangler.jsonc" },
			// Analytics SQL has no local implementation: keep tests fully local.
			remoteBindings: false,
			miniflare: {
				bindings: {
					// Test-only values (never used outside tests).
					TOKEN_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
					ADMIN_TOKEN: "test-admin-token",
					TARPIT_MS: "0",
					TEST_MIGRATIONS: await readD1Migrations(path.join(import.meta.dirname, "migrations")),
				},
			},
		})),
	],
	test: {
		// Only this checkout's tests (agent worktrees under .claude/ have their own copies).
		include: ["test/**/*.test.ts"],
		setupFiles: ["./test/apply-migrations.ts"],
	},
});
