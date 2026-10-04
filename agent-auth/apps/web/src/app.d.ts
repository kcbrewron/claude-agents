// See https://svelte.dev/docs/kit/types#app.d.ts
// Worker bindings are typed in worker-env.d.ts.
declare global {
	namespace App {
		interface Locals {
			/** The signed-in person's email, from Cloudflare Access. */
			user: string;
		}
	}
}

export {};
