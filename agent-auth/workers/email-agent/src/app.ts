/**
 * Email agent: can draft and send, but sending needs a scope nobody is granted.
 *
 * That's the point: if the assistant's LLM were tricked (say, by a prompt
 * injection hidden in a calendar invite) into trying to send email, the
 * authorization server would refuse to mint an `email:send` token for it.
 * Drafts wait for a human to review and send them.
 */
import { Hono } from "hono";
import { z } from "zod";
import { harden, requireAgent, verifierFromEnv, type AgentVariables, type ResourceServerEnv } from "@agent-auth/a2a";

export type Env = ResourceServerEnv & { DRAFTS: KVNamespace };
type App = { Bindings: Env; Variables: AgentVariables };

const Email = z.object({
  to: z.array(z.string().email()).min(1).max(50),
  subject: z.string().min(1).max(300),
  body: z.string().max(20_000),
});

export function createApp() {
  const app = harden(new Hono<App>());

  app.get("/drafts", requireAgent(verifierFromEnv, "email:draft"), async (c) => {
    const { keys } = await c.env.DRAFTS.list({ prefix: "draft:" });
    const drafts = await Promise.all(keys.map((k: { name: string }) => c.env.DRAFTS.get(k.name, "json")));
    return c.json({ drafts: drafts.filter(Boolean) });
  });

  app.post("/drafts", requireAgent(verifierFromEnv, "email:draft"), async (c) => {
    const parsed = Email.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "invalid_request", issues: parsed.error.issues }, 400);
    const draft = { ...parsed.data, id: crypto.randomUUID(), created_by: c.get("caller").agentId };
    await c.env.DRAFTS.put(`draft:${draft.id}`, JSON.stringify(draft));
    return c.json(draft, 201);
  });

  app.post("/send", requireAgent(verifierFromEnv, "email:send"), async (c) => {
    // A real implementation would use Cloudflare Email Routing's send_email binding.
    return c.json({ status: "sent", sent_by: c.get("caller").agentId });
  });

  return app;
}
