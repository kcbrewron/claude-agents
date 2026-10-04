/** Calendar agent: owns the calendar and only trusts verified callers. */
import { Hono } from "hono";
import { z } from "zod";
import { harden, requireAgent, verifierFromEnv, type AgentVariables, type ResourceServerEnv } from "@agent-auth/a2a";

export type Env = ResourceServerEnv & { EVENTS: KVNamespace };
type App = { Bindings: Env; Variables: AgentVariables };

const NewEvent = z.object({
  title: z.string().min(1).max(200),
  // ISO 8601 local date-time, e.g. 2026-10-10T09:00 (also keeps KV keys well-formed)
  start: z.iso.datetime({ local: true }),
  attendees: z.array(z.string().email()).max(50).default([]),
});

export function createApp() {
  const app = harden(new Hono<App>());

  app.get("/events", requireAgent(verifierFromEnv, "calendar:read"), async (c) => {
    // Keys are "event:<start>:<id>", so listing returns them in date order.
    const { keys } = await c.env.EVENTS.list({ prefix: "event:" });
    const events = await Promise.all(keys.map((k: { name: string }) => c.env.EVENTS.get(k.name, "json")));
    return c.json({ events: events.filter(Boolean), served_to: c.get("caller").agentId });
  });

  app.post("/events", requireAgent(verifierFromEnv, "calendar:write"), async (c) => {
    const parsed = NewEvent.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: "invalid_request", issues: parsed.error.issues }, 400);
    const event = { ...parsed.data, id: crypto.randomUUID(), created_by: c.get("caller").agentId };
    await c.env.EVENTS.put(`event:${event.start}:${event.id}`, JSON.stringify(event));
    return c.json(event, 201);
  });

  return app;
}
