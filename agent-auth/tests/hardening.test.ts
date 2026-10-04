/**
 * Edge cases: malformed requests, headers, error handling, and the less
 * common branches of the auth server, verifier and agents.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { SignJWT, decodeJwt, decodeProtectedHeader } from "jose";
import {
  CLIENT_ASSERTION_TYPE,
  MAX_BODY_BYTES,
  clearJwksCache,
  generateAgentKey,
  importPrivateKey,
  importPublicKey,
  publicPart,
} from "@agent-auth/a2a";
import { createApp as createAuthServer } from "../workers/auth-server/src/app";
import { ISSUER, URLS, buildNetwork } from "./network";

beforeEach(() => clearJwksCache());

const EVENTS = `${URLS["calendar-agent"]}/events`;
type Net = Awaited<ReturnType<typeof buildNetwork>>;

const token = (net: Net, form: Record<string, string>) =>
  net.auth.fetch(new Request(`${ISSUER}/token`, { method: "POST", body: new URLSearchParams(form) }));

async function validForm(net: Net, overrides: Record<string, string> = {}) {
  return {
    grant_type: "client_credentials",
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await net.assistantClient.clientAssertion(),
    resource: "calendar-agent",
    scope: "calendar:read",
    ...overrides,
  };
}

const errorOf = async (r: Response) => ((await r.json()) as { error: string }).error;

describe("security headers and HTTP hygiene on agents", () => {
  it("sends strict headers and no-store by default", async () => {
    const net = await buildNetwork();
    const r = await net.calendar.fetch(new Request(EVENTS));
    expect(r.status).toBe(401);
    expect(r.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("strict-transport-security")).toMatch(/max-age=63072000/);
    expect(r.headers.get("cache-control")).toBe("no-store");
  });

  it("lets only public metadata be cached", async () => {
    const net = await buildNetwork();
    for (const path of ["/.well-known/jwks.json", "/.well-known/oauth-authorization-server"]) {
      const r = await net.auth.fetch(new Request(ISSUER + path));
      expect(r.headers.get("cache-control")).toBe("public, max-age=300");
    }
    const t = await token(net, await validForm(net));
    expect(t.headers.get("cache-control")).toBe("no-store");
  });

  it("answers unknown routes with JSON 404", async () => {
    const net = await buildNetwork();
    const r = await net.email.fetch(new Request(`${URLS["email-agent"]}/nope`));
    expect(r.status).toBe(404);
    expect(await errorOf(r)).toBe("not_found");
  });

  it("rejects oversized bodies before authentication", async () => {
    const net = await buildNetwork();
    const body = "x".repeat(MAX_BODY_BYTES + 1);
    const r = await net.calendar.fetch(
      new Request(EVENTS, { method: "POST", body, headers: { "content-length": String(body.length) } }),
    );
    expect(r.status).toBe(413);
  });

  it("hides internal error details", async () => {
    const r = await createAuthServer().fetch(new Request(`${ISSUER}/.well-known/jwks.json`), {
      SIGNING_KEY: "not json",
    } as never);
    expect(r.status).toBe(500);
    expect(await r.json()).toEqual({ error: "server_error", error_description: "internal error" });
  });
});

describe("auth server request validation", () => {
  it("publishes a discovery document", async () => {
    const net = await buildNetwork();
    const meta = (await (await net.auth.fetch(new Request(`${ISSUER}/.well-known/oauth-authorization-server`))).json()) as Record<string, unknown>;
    expect(meta).toMatchObject({ issuer: ISSUER, token_endpoint: `${ISSUER}/token` });
  });

  it("only supports client_credentials", async () => {
    const net = await buildNetwork();
    const r = await token(net, await validForm(net, { grant_type: "password" }));
    expect(await errorOf(r)).toBe("unsupported_grant_type");
  });

  it("only supports private_key_jwt client authentication", async () => {
    const net = await buildNetwork();
    const r = await token(net, await validForm(net, { client_assertion_type: "urn:other" }));
    expect(r.status).toBe(401);
  });

  it("rejects a malformed assertion", async () => {
    const net = await buildNetwork();
    const r = await token(net, await validForm(net, { client_assertion: "garbage" }));
    expect(await errorOf(r)).toBe("invalid_client");
  });

  it("rejects a client_id that disagrees with the assertion", async () => {
    const net = await buildNetwork();
    const r = await token(net, await validForm(net, { client_id: "web-ui" }));
    expect(await errorOf(r)).toBe("invalid_client");
  });

  it("rejects a long-lived assertion", async () => {
    const net = await buildNetwork();
    const real = decodeJwt(await net.assistantClient.clientAssertion());
    const longLived = await new SignJWT({ ...real, exp: (real.iat as number) + 3600, jti: "long" })
      .setProtectedHeader({ alg: "EdDSA" })
      .sign(await importPrivateKey(assistantPrivate(net)));
    const r = await token(net, await validForm(net, { client_assertion: longLived }));
    expect(((await r.json()) as { error_description: string }).error_description).toMatch(/lifetime/);
  });

  it("requires at least one scope", async () => {
    const net = await buildNetwork();
    const r = await token(net, await validForm(net, { scope: "" }));
    expect(await errorOf(r)).toBe("invalid_scope");
  });
});

const assistantPrivate = (net: Net) => net.assistantKey.privateJwk;

describe("verifier edge cases", () => {
  async function callWith(net: Net, headers: Record<string, string>) {
    return net.calendar.fetch(new Request(EVENTS, { headers }));
  }

  it("requires a DPoP proof alongside the token", async () => {
    const net = await buildNetwork();
    const t = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const r = await callWith(net, { authorization: `DPoP ${t}` });
    expect(((await r.json()) as { error_description: string }).error_description).toMatch(/missing DPoP/);
  });

  it("rejects a proof without an embedded key", async () => {
    const net = await buildNetwork();
    const t = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const proof = await new SignJWT({ htm: "GET", htu: EVENTS })
      .setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt" })
      .setIssuedAt()
      .setJti("j")
      .sign(await importPrivateKey(assistantPrivate(net)));
    const r = await callWith(net, { authorization: `DPoP ${t}`, dpop: proof });
    expect(r.status).toBe(401);
  });

  it("rejects a token signed with an unknown key id", async () => {
    const net = await buildNetwork();
    const t = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const other = await generateAgentKey();
    const forged = await new SignJWT(decodeJwt(t))
      .setProtectedHeader({ ...decodeProtectedHeader(t), kid: "nope" } as never)
      .sign(await importPrivateKey(other.privateJwk));
    const r = await callWith(net, {
      authorization: `DPoP ${forged}`,
      dpop: await net.assistantClient.dpopProof("GET", EVENTS, forged),
    });
    expect(((await r.json()) as { error_description: string }).error_description).toMatch(/unknown signing key/);
  });

  it("rejects a JWT that is not an access token", async () => {
    const net = await buildNetwork();
    const assertion = await net.assistantClient.clientAssertion(); // a valid JWT, wrong kind
    const r = await callWith(net, {
      authorization: `DPoP ${assertion}`,
      dpop: await net.assistantClient.dpopProof("GET", EVENTS, assertion),
    });
    expect(r.status).toBe(401);
  });

  it("fails safely when the issuer's keys can't be fetched", async () => {
    const net = await buildNetwork();
    const t = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const { createApp } = await import("../workers/calendar-agent/src/app");
    const r = await createApp().fetch(
      new Request(EVENTS, { headers: { authorization: `DPoP ${t}`, dpop: await net.assistantClient.dpopProof("GET", EVENTS, t) } }),
      {
        AGENT_ID: "calendar-agent",
        SELF_URL: URLS["calendar-agent"],
        ISSUER,
        AUTH: { fetch: async () => new Response("down", { status: 503 }) },
        REPLAY: { idFromName: () => "x", get: () => ({ checkAndStore: async () => true }) },
      } as never,
    );
    expect(r.status).toBe(401);
    expect(((await r.json()) as { error_description: string }).error_description).toMatch(/issuer keys/);
  });

  it("keeps header-unsafe characters out of WWW-Authenticate", async () => {
    const net = await buildNetwork();
    const real = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    // An expired token produces a jose message containing double quotes.
    const old = Math.floor(Date.now() / 1000) - 3600;
    const expired = await new SignJWT({ ...decodeJwt(real), iat: old, nbf: old, exp: old + 60 })
      .setProtectedHeader(decodeProtectedHeader(real) as never)
      .sign(await importPrivateKey(net.as.privateJwk));
    const r = await callWith(net, {
      authorization: `DPoP ${expired}`,
      dpop: await net.assistantClient.dpopProof("GET", EVENTS, expired),
    });
    const header = r.headers.get("www-authenticate")!;
    const description = header.match(/error_description="([^"]*)"/)![1];
    expect(description).toMatch(/'exp'/);
  });
});

describe("key handling", () => {
  it("refuses non-Ed25519 keys and private key material", async () => {
    const { privateJwk, publicJwk } = await generateAgentKey();
    await expect(importPublicKey({ kty: "RSA", n: "x", e: "AQAB" })).rejects.toThrow(/Ed25519/);
    await expect(importPublicKey(privateJwk)).rejects.toThrow(/private key/);
    await expect(importPublicKey(publicPart(publicJwk))).resolves.toBeTruthy();
  });

  it("refuses to call an agent it has no binding for", async () => {
    const net = await buildNetwork();
    await expect(net.assistantClient.request("weather-agent", "GET", "/", ["x"])).rejects.toThrow(/no service binding/);
  });
});

describe("agents validate input", () => {
  it("calendar rejects a start that isn't an ISO date-time", async () => {
    const net = await buildNetwork();
    const r = await net.assistantClient.request("calendar-agent", "POST", "/events", ["calendar:write"], {
      title: "x",
      start: "next tuesday-ish",
    });
    expect(r.status).toBe(400);
  });

  it("email rejects invalid drafts and lists saved ones", async () => {
    const net = await buildNetwork();
    const bad = await net.assistantClient.request("email-agent", "POST", "/drafts", ["email:draft"], { to: [] });
    expect(bad.status).toBe(400);
    await net.assistantClient.request("email-agent", "POST", "/drafts", ["email:draft"], {
      to: ["a@example.com"],
      subject: "s",
      body: "b",
    });
    const list = await net.assistantClient.request("email-agent", "GET", "/drafts", ["email:draft"]);
    expect(((await list.json()) as { drafts: unknown[] }).drafts).toHaveLength(1);
  });

  it("email can send only if policy grants email:send", async () => {
    const net = await buildNetwork([], { assistant: { "email-agent": ["email:send"] } });
    const r = await net.assistantClient.request("email-agent", "POST", "/send", ["email:send"], {
      to: ["a@example.com"],
      subject: "s",
      body: "b",
    });
    expect(r.status).toBe(200);
  });
});
