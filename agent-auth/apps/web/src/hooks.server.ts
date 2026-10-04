/**
 * Human-to-app authentication, handled by Cloudflare Access.
 *
 * Access sits in front of this Worker and signs you in (Google, GitHub, a
 * one-time email PIN...). It then forwards each request with a signed JWT in
 * the `Cf-Access-Jwt-Assertion` header. We verify that JWT ourselves rather
 * than trusting that Access is configured, so that someone reaching the
 * Worker another way can't skip the login.
 *
 * This fails closed: with no Access settings, every request is refused. The
 * local-dev bypass needs BOTH ALLOW_UNAUTHENTICATED_DEV=true (only ever set in
 * .dev.vars) AND a localhost URL, so a stray production variable can't open it.
 *
 * Every response, including refusals, gets security headers and
 * `Cache-Control: private, no-store` (pages contain the signed-in user's data).
 * The CSP itself is configured in vite.config.ts so SvelteKit can add nonces.
 */
import type { Handle } from '@sveltejs/kit/hooks';
import { env } from 'cloudflare:workers';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const SECURITY_HEADERS: Record<string, string> = {
	'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
	'X-Content-Type-Options': 'nosniff',
	'X-Frame-Options': 'DENY',
	'Referrer-Policy': 'no-referrer',
	'Cross-Origin-Opener-Policy': 'same-origin',
	'Cross-Origin-Resource-Policy': 'same-origin',
	'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
	'Cache-Control': 'private, no-store'
};

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

const jwksByTeam = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function accessKeys(teamDomain: string) {
	let jwks = jwksByTeam.get(teamDomain);
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(`https://${teamDomain}/cdn-cgi/access/certs`));
		jwksByTeam.set(teamDomain, jwks);
	}
	return jwks;
}

function withSecurityHeaders(response: Response): Response {
	for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.headers.set(name, value);
	return response;
}

const refuse = (status: number, message: string) =>
	new Response(message, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });

/** Returns the signed-in user's email, or a refusal Response. */
async function authenticate(request: Request, url: URL): Promise<string | Response> {
	if (env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD) {
		const token = request.headers.get('cf-access-jwt-assertion');
		if (!token) return refuse(401, 'Sign in through Cloudflare Access');
		try {
			const { payload } = await jwtVerify(token, accessKeys(env.ACCESS_TEAM_DOMAIN), {
				issuer: `https://${env.ACCESS_TEAM_DOMAIN}`,
				audience: env.ACCESS_AUD
			});
			const user = payload.email ?? payload.sub;
			if (typeof user !== 'string' || !user) return refuse(401, 'Access token has no identity');
			return user;
		} catch {
			return refuse(401, 'Invalid Access token');
		}
	}
	if (env.ALLOW_UNAUTHENTICATED_DEV === 'true' && LOCAL_HOSTS.has(url.hostname)) {
		return 'dev@localhost';
	}
	return refuse(503, 'Cloudflare Access is not configured for this Worker');
}

export const handle: Handle = async ({ event, resolve }) => {
	const user = await authenticate(event.request, event.url);
	if (user instanceof Response) return withSecurityHeaders(user);
	event.locals.user = user;
	return withSecurityHeaders(await resolve(event));
};
