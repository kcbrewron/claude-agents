/**
 * The personal assistant Worker.
 *
 * It plays both roles in agent-to-agent auth:
 *   - resource server: the web UI calls POST /chat with a token for scope
 *     `assistant:chat`, verified like any other agent call;
 *   - client: for each tool the model picks, it asks the authorization server
 *     for a narrow, short-lived token for exactly that agent and scope.
 *
 * It holds no calendar or email credentials of its own.
 */
import { Hono } from "hono";
import { z } from "zod";
import type { JWK } from "jose";
import {
  AgentClient,
  harden,
  requireAgent,
  verifierFromEnv,
  type AgentVariables,
  type Fetcher,
  type ResourceServerEnv,
} from "@agent-auth/a2a";
import { runAssistant, type AiBinding } from "./agent";

export type Env = ResourceServerEnv & {
  AGENT_PRIVATE_KEY: string;
  CALENDAR: Fetcher;
  CALENDAR_URL: string;
  EMAIL: Fetcher;
  EMAIL_URL: string;
  AI: AiBinding;
  AI_MODEL: string;
};
type App = { Bindings: Env; Variables: AgentVariables };

const ChatRequest = z.object({
  message: z.string().min(1).max(4000),
  user: z.string().max(320).optional(),
});

// One client per isolate, so issued tokens are reused until they near expiry.
const clients = new WeakMap<object, AgentClient>();
function clientFor(env: Env): AgentClient {
  let client = clients.get(env);
  if (!client) {
    client = new AgentClient({
      agentId: env.AGENT_ID,
      privateJwk: JSON.parse(env.AGENT_PRIVATE_KEY) as JWK,
      issuer: env.ISSUER,
      auth: env.AUTH,
      services: {
        "calendar-agent": { url: env.CALENDAR_URL, fetcher: env.CALENDAR },
        "email-agent": { url: env.EMAIL_URL, fetcher: env.EMAIL },
      },
    });
    clients.set(env, client);
  }
  return client;
}

export function createApp() {
  const app = harden(new Hono<App>());

  app.post("/chat", requireAgent(verifierFromEnv, "assistant:chat"), async (c) => {
    const parsed = ChatRequest.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "invalid_request", issues: parsed.error.issues }, 400);
    // `user` is trusted only because the caller is the authenticated web-ui
    // agent, which got it from Cloudflare Access. See README "Delegation".
    try {
      const result = await runAssistant({
        ai: c.env.AI,
        model: c.env.AI_MODEL,
        client: clientFor(c.env),
        message: parsed.data.message,
        user: parsed.data.user,
      });
      return c.json(result);
    } catch (e) {
      // Details go to Workers Logs, not to the caller.
      console.error("assistant failed", e);
      return c.json({ error: "assistant_failed", error_description: "the assistant could not complete this request" }, 502);
    }
  });

  return app;
}
