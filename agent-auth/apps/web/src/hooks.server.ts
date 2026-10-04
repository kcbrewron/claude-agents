/**
 * Human-to-app authentication, handled by Cloudflare Access.
 *
 * Access sits in front of this Worker and signs you in (Google, GitHub, a
 * one-time email PIN...). It then forwards each request with a signed JWT in
 * the `Cf-Access-Jwt-Assertion` header. We verify that JWT ourselves rather
 * than trusting that Access is configured, so that someone reaching the
 * Worker another way can't skip the login.
 *
 * This fails closed: with no Access settings, every request is refused,
 * unless ALLOW_UNAUTHENTICATED_DEV=true (only ever set in .dev.vars).
 */
import type { Handle } from '@sveltejs/kit/hooks';
import { env } from 'cloudflare:workers';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const jwksByTeam = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function accessKeys(teamDomain: string) {
	let jwks = jwksByTeam.get(teamDomain);
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(`https://${teamDomain}/cdn-cgi/access/certs`));
		jwksByTeam.set(teamDomain, jwks);
	}
	return jwks;
}

export const handle: Handle = async ({ event, resolve }) => {
	if (env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD) {
		const token = event.request.headers.get('cf-access-jwt-assertion');
		if (!token) return new Response('Sign in through Cloudflare Access', { status: 401 });
		try {
			const { payload } = await jwtVerify(token, accessKeys(env.ACCESS_TEAM_DOMAIN), {
				issuer: `https://${env.ACCESS_TEAM_DOMAIN}`,
				audience: env.ACCESS_AUD
			});
			event.locals.user = String(payload.email ?? payload.sub);
		} catch {
			return new Response('Invalid Access token', { status: 401 });
		}
	} else if (env.ALLOW_UNAUTHENTICATED_DEV === 'true') {
		event.locals.user = 'dev@localhost';
	} else {
		return new Response('Cloudflare Access is not configured for this Worker', { status: 503 });
	}

	return resolve(event);
};
