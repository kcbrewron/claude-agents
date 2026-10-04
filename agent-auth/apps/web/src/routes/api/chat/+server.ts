import { error, json } from '@sveltejs/kit';
import { env } from 'cloudflare:workers';
import { TokenRequestError } from '@agent-auth/a2a';
import { assistantClient } from '#lib/server/assistant.js';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request, locals }) => {
	// Only JSON. Browsers can't send application/json cross-site without a CORS
	// preflight (which we never approve), so this also blocks CSRF in depth,
	// on top of SvelteKit's own origin check for form-like content types.
	if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
		error(415, 'expected application/json');
	}
	const { message } = (await request.json().catch(() => ({}))) as { message?: unknown };
	if (typeof message !== 'string' || !message.trim() || message.length > 4000) {
		error(400, 'message must be 1-4000 characters');
	}

	try {
		const resp = await assistantClient(env).request(
			'assistant',
			'POST',
			'/chat',
			['assistant:chat'],
			{ message, user: locals.user }
		);
		const body = await resp.json().catch(() => null);
		if (body === null) error(502, `assistant returned ${resp.status}`);
		return json(body, { status: resp.status });
	} catch (e) {
		if (e instanceof TokenRequestError) error(502, `auth server refused the web UI: ${e.message}`);
		throw e;
	}
};
