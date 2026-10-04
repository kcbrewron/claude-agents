/**
 * The web UI is itself an agent ("web-ui") with its own key pair. To reach the
 * assistant it gets an `assistant:chat` token and signs a DPoP proof, exactly
 * like the assistant does when it calls the calendar agent.
 */
import { AgentClient } from '@agent-auth/a2a';
import type { JWK } from 'jose';
import type { WebEnv } from 'cloudflare:workers';

// One client per isolate, so tokens are reused until they near expiry.
const clients = new WeakMap<object, AgentClient>();

export function assistantClient(env: WebEnv): AgentClient {
	let client = clients.get(env);
	if (!client) {
		client = new AgentClient({
			agentId: env.AGENT_ID,
			privateJwk: JSON.parse(env.AGENT_PRIVATE_KEY) as JWK,
			issuer: env.ISSUER,
			auth: env.AUTH,
			services: { assistant: { url: env.ASSISTANT_URL, fetcher: env.ASSISTANT } }
		});
		clients.set(env, client);
	}
	return client;
}
