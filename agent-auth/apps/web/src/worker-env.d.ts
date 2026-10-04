// adapter-cloudflare exposes bindings the same way a plain Worker gets them:
//   import { env } from 'cloudflare:workers';
// Declared here rather than via @cloudflare/workers-types, whose globals clash
// with the browser DOM types SvelteKit uses.
declare module 'cloudflare:workers' {
	import type { Fetcher } from '@agent-auth/a2a';

	/** This Worker's bindings (see wrangler.jsonc). */
	export interface WebEnv {
		AGENT_ID: string;
		AGENT_PRIVATE_KEY: string;
		ISSUER: string;
		ASSISTANT_URL: string;
		ACCESS_TEAM_DOMAIN: string;
		ACCESS_AUD: string;
		/** Set to "true" in .dev.vars only, to skip Access when running locally. */
		ALLOW_UNAUTHENTICATED_DEV?: string;
		AUTH: Fetcher;
		ASSISTANT: Fetcher;
	}

	export const env: WebEnv;
}
