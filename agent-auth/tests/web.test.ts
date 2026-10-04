/**
 * The web Worker is the only public entry point, so it gets the most scrutiny:
 * login (Cloudflare Access), fail-closed behaviour, headers, and input checks.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from "jose";
import { clearJwksCache } from "@agent-auth/a2a";
import { env } from "cloudflare:workers";
import { handle } from "../apps/web/src/hooks.server";
import { POST } from "../apps/web/src/routes/api/chat/+server";
import { assistantClient } from "../apps/web/src/lib/server/assistant";
import { load } from "../apps/web/src/routes/+page.server";
import { ISSUER, URLS, buildNetwork } from "./network";

const TEAM = "team.cloudflareaccess.com";
const AUD = "access-aud-tag";

let accessKey: CryptoKey;
let accessJwk: JWK;

beforeAll(async () => {
  // Cloudflare Access signs with RS256.
  const pair = await generateKeyPair("RS256");
  accessKey = pair.privateKey;
  accessJwk = { ...(await exportJWK(pair.publicKey)), kid: "access-1", alg: "RS256" };
});

beforeEach(() => {
  for (const k of Object.keys(env)) delete env[k];
  clearJwksCache();
  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    if (String(input) === `https://${TEAM}/cdn-cgi/access/certs`) {
      return Response.json({ keys: [accessJwk] });
    }
    throw new Error(`unexpected fetch ${input}`);
  });
});
afterEach(() => vi.unstubAllGlobals());

function accessToken(claims: Record<string, unknown> = { email: "ron@example.com" }, aud = AUD) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "access-1" })
    .setIssuer(`https://${TEAM}`)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(accessKey);
}

async function runHook(url: string, headers: Record<string, string> = {}) {
  const event = { request: new Request(url, { headers }), url: new URL(url), locals: {} as { user?: string } };
  const resolve = vi.fn(async () => new Response("page"));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const response = await handle({ event, resolve } as any);
  return { response, resolve, user: event.locals.user };
}

describe("login (hooks.server.ts)", () => {
  it("fails closed when Access is not configured", async () => {
    const { response, resolve } = await runHook("https://a2a-web.example.workers.dev/");
    expect(response.status).toBe(503);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("ignores the dev bypass on a public hostname", async () => {
    env.ALLOW_UNAUTHENTICATED_DEV = "true";
    const { response, resolve } = await runHook("https://a2a-web.example.workers.dev/");
    expect(response.status).toBe(503);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("allows the dev bypass on localhost only", async () => {
    env.ALLOW_UNAUTHENTICATED_DEV = "true";
    const { response, user } = await runHook("http://localhost:8787/");
    expect(response.status).toBe(200);
    expect(user).toBe("dev@localhost");
  });

  describe("with Access configured", () => {
    beforeEach(() => {
      env.ACCESS_TEAM_DOMAIN = TEAM;
      env.ACCESS_AUD = AUD;
      env.ALLOW_UNAUTHENTICATED_DEV = "true"; // must be ignored once Access is on
    });

    it("rejects a request with no Access token, even on localhost", async () => {
      const { response, resolve } = await runHook("http://localhost:8787/");
      expect(response.status).toBe(401);
      expect(resolve).not.toHaveBeenCalled();
    });

    it("accepts a valid Access token and records the user", async () => {
      const token = await accessToken();
      const { response, user } = await runHook("https://app.example/", { "cf-access-jwt-assertion": token });
      expect(response.status).toBe(200);
      expect(user).toBe("ron@example.com");
    });

    it("rejects a token for another Access application", async () => {
      const token = await accessToken({ email: "ron@example.com" }, "some-other-app");
      const { response } = await runHook("https://app.example/", { "cf-access-jwt-assertion": token });
      expect(response.status).toBe(401);
    });

    it("rejects a forged token", async () => {
      const { privateKey } = await generateKeyPair("RS256");
      const forged = await new SignJWT({ email: "ron@example.com" })
        .setProtectedHeader({ alg: "RS256", kid: "access-1" })
        .setIssuer(`https://${TEAM}`)
        .setAudience(AUD)
        .setExpirationTime("5m")
        .sign(privateKey);
      const { response } = await runHook("https://app.example/", { "cf-access-jwt-assertion": forged });
      expect(response.status).toBe(401);
    });

    it("rejects a token with no identity", async () => {
      const token = await accessToken({});
      const { response } = await runHook("https://app.example/", { "cf-access-jwt-assertion": token });
      expect(response.status).toBe(401);
    });
  });

  it("adds security and cache headers to every response, including refusals", async () => {
    for (const { response } of [
      await runHook("https://a2a-web.example.workers.dev/"),
      await (async () => {
        env.ALLOW_UNAUTHENTICATED_DEV = "true";
        return runHook("http://localhost:8787/");
      })(),
    ]) {
      expect(response.headers.get("cache-control")).toBe("private, no-store");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(response.headers.get("x-frame-options")).toBe("DENY");
      expect(response.headers.get("strict-transport-security")).toMatch(/max-age=\d+/);
      expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    }
  });
});

describe("POST /api/chat", () => {
  let net: Awaited<ReturnType<typeof buildNetwork>>;
  // The web client is cached per isolate, so route its bindings through
  // switchable stand-ins instead of replacing them between tests.
  let authTarget: { fetch(r: Request): Promise<Response> };
  let assistantTarget: { fetch(r: Request): Promise<Response> };

  beforeAll(async () => {
    net = await buildNetwork([{ response: "Your calendar is empty." }, { response: "second" }]);
  });

  beforeEach(() => {
    authTarget = net.auth;
    assistantTarget = net.assistant;
    Object.assign(env, {
      AGENT_ID: "web-ui",
      AGENT_PRIVATE_KEY: JSON.stringify(net.webKey.privateJwk),
      ISSUER,
      ASSISTANT_URL: URLS.assistant,
      AUTH: { fetch: (r: Request) => authTarget.fetch(r) },
      ASSISTANT: { fetch: (r: Request) => assistantTarget.fetch(r) },
    });
  });

  const call = (body: unknown, contentType = "application/json") =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    POST({
      request: new Request("https://app.example/api/chat", {
        method: "POST",
        headers: { "content-type": contentType },
        body: typeof body === "string" ? body : JSON.stringify(body),
      }),
      locals: { user: "ron@example.com" },
    } as any);

  it("relays a chat to the assistant as the web-ui agent", async () => {
    const resp = await call({ message: "what's on today?" });
    expect(resp.status).toBe(200);
    expect(((await resp.json()) as { reply: string }).reply).toBe("Your calendar is empty.");
    // The assistant saw the user from Access, passed along by the web UI.
    expect(net.ai.calls[0].input.messages[0].content).toContain("ron@example.com");
  });

  it("rejects non-JSON bodies (CSRF defense in depth)", async () => {
    await expect(call('{"message":"hi"}', "text/plain")).rejects.toMatchObject({ status: 415 });
  });

  it.each([[{}], [{ message: "" }], [{ message: "   " }], [{ message: 42 }], [{ message: "x".repeat(4001) }], ["not json"]])(
    "rejects invalid input %#",
    async (body) => {
      await expect(call(body)).rejects.toMatchObject({ status: 400 });
    },
  );

  it("reports 502 when the auth server refuses the web UI", async () => {
    authTarget = { fetch: async () => Response.json({ error: "invalid_target" }, { status: 400 }) };
    assistantClient(env as never).clearTokens(); // make it ask the (refusing) auth server
    await expect(call({ message: "hi" })).rejects.toMatchObject({ status: 502 });
  });

  it("reports 502 when the assistant returns something that is not JSON", async () => {
    assistantTarget = { fetch: async () => new Response("Internal Server Error", { status: 500 }) };
    await expect(call({ message: "hi" })).rejects.toMatchObject({ status: 502 });
  });

  it("lets other failures surface as errors", async () => {
    assistantTarget = {
      fetch: async () => {
        throw new TypeError("network down");
      },
    };
    await expect(call({ message: "hi" })).rejects.toThrow("network down");
  });
});

it("page load exposes only the signed-in user", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  expect(load({ locals: { user: "ron@example.com" } } as any)).toEqual({ user: "ron@example.com" });
});
