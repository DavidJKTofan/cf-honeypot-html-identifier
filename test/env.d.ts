declare namespace Cloudflare {
	interface Env {
		TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
	}
}

/** Vite `?raw` imports (used to read src/admin/openapi.yaml in tests). */
declare module "*?raw" {
	const content: string;
	export default content;
}
