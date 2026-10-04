/**
 * Wires the real Hono apps together in one process, with small fakes standing
 * in for Cloudflare bindings:
 *   service binding  -> { fetch: req => otherApp.fetch(req, otherEnv) }
 *   Durable Object   -> MemoryReplayStore
 *   KV namespace     -> Map
 *   Workers AI       -> a scripted list of model outputs
 */
import { AgentClient, MemoryReplayStore, generateAgentKey, type ReplayNamespace } from "@agent-auth/a2a";
import type { JWK } from "jose";
import { createApp as createAuthServer } from "../workers/auth-server/src/app";
import { createApp as createAssistant } from "../workers/assistant/src/app";
import { createApp as createCalendar } from "../workers/calendar-agent/src/app";
import { createApp as createEmail } from "../workers/email-agent/src/app";

export const ISSUER = "https://auth.agents.internal";
export const URLS = {
  assistant: "https://assistant.agents.internal",
  "calendar-agent": "https://calendar.agents.internal",
  "email-agent": "https://email.agents.internal",
};

function fakeReplayNamespace(): ReplayNamespace {
  const stores = new Map<string, MemoryReplayStore>();
  return {
    idFromName: (name: string) => name,
    get: ((id: string) => {
      if (!stores.has(id)) stores.set(id, new MemoryReplayStore());
      return stores.get(id)!;
    }) as ReplayNamespace["get"],
  };
}

function fakeKV() {
  const data = new Map<string, string>();
  return {
    data,
    async get(key: string, type?: "json") {
      const v = data.get(key);
      return v === undefined ? null : type === "json" ? JSON.parse(v) : v;
    },
    async put(key: string, value: string) {
      data.set(key, value);
    },
    async list({ prefix = "" } = {}) {
      const keys = [...data.keys()].filter((k) => k.startsWith(prefix)).sort();
      return { keys: keys.map((name) => ({ name })), list_complete: true };
    },
  } as unknown as KVNamespace & { data: Map<string, string> };
}

export type ModelOutput = { response?: string; tool_calls?: { name: string; arguments: object }[] };

export class FakeAI {
  calls: { model: string; input: any }[] = [];
  constructor(private script: ModelOutput[]) {}
  async run(model: string, input: any) {
    this.calls.push({ model, input: structuredClone(input) });
    return this.script.shift() ?? { response: "(script exhausted)" };
  }
}

const bind = (app: { fetch: Function }, env: object) => ({
  fetch: (req: Request) => app.fetch(req, env) as Promise<Response>,
});

export async function buildNetwork(script: ModelOutput[] = []) {
  const [as, assistantKey, webKey] = await Promise.all([generateAgentKey(), generateAgentKey(), generateAgentKey()]);
  const agentPublicKeys: Record<string, JWK> = { assistant: assistantKey.publicJwk, "web-ui": webKey.publicJwk };

  const authEnv = {
    ISSUER,
    SIGNING_KEY: JSON.stringify(as.privateJwk),
    AGENT_PUBLIC_KEYS: JSON.stringify(agentPublicKeys),
    REPLAY: fakeReplayNamespace(),
  };
  const auth = bind(createAuthServer(), authEnv);

  const resourceEnv = (id: string, url: string) => ({
    AGENT_ID: id, SELF_URL: url, ISSUER, AUTH: auth, REPLAY: fakeReplayNamespace(),
  });
  const events = fakeKV();
  const drafts = fakeKV();
  const calendar = bind(createCalendar(), { ...resourceEnv("calendar-agent", URLS["calendar-agent"]), EVENTS: events });
  const email = bind(createEmail(), { ...resourceEnv("email-agent", URLS["email-agent"]), DRAFTS: drafts });

  const ai = new FakeAI(script);
  const assistant = bind(createAssistant(), {
    ...resourceEnv("assistant", URLS.assistant),
    AGENT_PRIVATE_KEY: JSON.stringify(assistantKey.privateJwk),
    CALENDAR: calendar,
    CALENDAR_URL: URLS["calendar-agent"],
    EMAIL: email,
    EMAIL_URL: URLS["email-agent"],
    AI: ai,
    AI_MODEL: "@cf/test/model",
  });

  const services = {
    assistant: { url: URLS.assistant, fetcher: assistant },
    "calendar-agent": { url: URLS["calendar-agent"], fetcher: calendar },
    "email-agent": { url: URLS["email-agent"], fetcher: email },
  };
  const clientFor = (agentId: string, privateJwk: JWK) =>
    new AgentClient({ agentId, privateJwk, issuer: ISSUER, auth, services });

  return {
    auth, calendar, email, assistant, ai, events, drafts, as,
    webUi: clientFor("web-ui", webKey.privateJwk),
    // Acting *as* the assistant, to probe the calendar/email agents directly.
    assistantClient: clientFor("assistant", assistantKey.privateJwk),
    clientFor,
  };
}
