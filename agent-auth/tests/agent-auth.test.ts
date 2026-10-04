/** Each test pins down one security property of the agent-to-agent protocol. */
import { beforeEach, describe, expect, it } from "vitest";
import { SignJWT, decodeJwt, decodeProtectedHeader } from "jose";
import {
  CLIENT_ASSERTION_TYPE,
  TokenRequestError,
  clearJwksCache,
  generateAgentKey,
  importPrivateKey,
  thumbprint,
} from "@agent-auth/a2a";
import { ISSUER, URLS, buildNetwork } from "./network";

beforeEach(() => clearJwksCache());

const EVENTS = `${URLS["calendar-agent"]}/events`;
const tokenForm = (assertion: string, extra: Record<string, string> = {}) =>
  new Request(`${ISSUER}/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
      resource: "calendar-agent",
      scope: "calendar:read",
      ...extra,
    }),
  });

describe("happy path", () => {
  it("assistant reads and writes the calendar", async () => {
    const net = await buildNetwork();
    const created = await net.assistantClient.request("calendar-agent", "POST", "/events", ["calendar:write"], {
      title: "Dentist", start: "2026-10-10T09:00", attendees: ["me@example.com"],
    });
    expect(created.status).toBe(201);
    const list = await net.assistantClient.request("calendar-agent", "GET", "/events", ["calendar:read"]);
    const body = (await list.json()) as any;
    expect(body.events.map((e: any) => e.title)).toEqual(["Dentist"]);
    expect(body.served_to).toBe("assistant");
  });

  it("issues audience-scoped, short-lived, key-bound tokens", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const claims = decodeJwt(token) as any;
    expect(decodeProtectedHeader(token).typ).toBe("at+jwt");
    expect(claims.aud).toBe("calendar-agent");
    expect(claims.scope).toBe("calendar:read");
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(300);
    expect(claims.cnf.jkt).toBeTruthy();
  });
});

describe("authorization server", () => {
  it("refuses a scope the policy does not grant", async () => {
    const net = await buildNetwork();
    const err = await net.assistantClient.getToken("email-agent", ["email:send"]).catch((e) => e);
    expect(err).toBeInstanceOf(TokenRequestError);
    expect(err.body.error).toBe("invalid_scope");
  });

  it("refuses a target the agent may not call at all", async () => {
    const net = await buildNetwork();
    const err = await net.webUi.getToken("calendar-agent", ["calendar:read"]).catch((e) => e);
    expect(err.body.error).toBe("invalid_target");
  });

  it("refuses an unregistered agent", async () => {
    const net = await buildNetwork();
    const rogue = net.clientFor("rogue", (await generateAgentKey()).privateJwk);
    const err = await rogue.getToken("calendar-agent", ["calendar:read"]).catch((e) => e);
    expect(err.body.error).toBe("invalid_client");
  });

  it("refuses an assertion claiming to be the assistant but signed by another key", async () => {
    const net = await buildNetwork();
    const impostor = net.clientFor("assistant", (await generateAgentKey()).privateJwk);
    const err = await impostor.getToken("calendar-agent", ["calendar:read"]).catch((e) => e);
    expect(err.status).toBe(401);
    expect(err.body.error).toBe("invalid_client");
  });

  it("refuses a replayed client assertion", async () => {
    const net = await buildNetwork();
    const assertion = await net.assistantClient.clientAssertion();
    expect((await net.auth.fetch(tokenForm(assertion))).status).toBe(200);
    const replay = await net.auth.fetch(tokenForm(assertion));
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as any).error_description).toMatch(/already used/);
  });

  it("publishes only the public half of its signing key", async () => {
    const net = await buildNetwork();
    const { keys } = (await (await net.auth.fetch(new Request(`${ISSUER}/.well-known/jwks.json`))).json()) as any;
    expect(keys).toHaveLength(1);
    expect(keys[0].d).toBeUndefined();
  });
});

describe("receiving agent", () => {
  const get = (net: Awaited<ReturnType<typeof buildNetwork>>, headers: Record<string, string>) =>
    net.calendar.fetch(new Request(EVENTS, { headers }));

  it("rejects a token presented as a plain Bearer token", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const r = await get(net, { authorization: `Bearer ${token}` });
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toMatch(/^DPoP/);
  });

  it("rejects a stolen token used with the thief's own DPoP key", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const thief = net.clientFor("thief", (await generateAgentKey()).privateJwk);
    const r = await get(net, { authorization: `DPoP ${token}`, dpop: await thief.dpopProof("GET", EVENTS, token) });
    expect(r.status).toBe(401);
    expect(((await r.json()) as any).error_description).toMatch(/does not match/);
  });

  it("rejects a replayed request", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const headers = { authorization: `DPoP ${token}`, dpop: await net.assistantClient.dpopProof("GET", EVENTS, token) };
    expect((await get(net, headers)).status).toBe(200);
    const replay = await get(net, headers);
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as any).error_description).toMatch(/replayed/);
  });

  it("rejects a proof made for a different URL", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const proof = await net.assistantClient.dpopProof("GET", `${URLS["calendar-agent"]}/other`, token);
    expect((await get(net, { authorization: `DPoP ${token}`, dpop: proof })).status).toBe(401);
  });

  it("rejects a token issued for another agent", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("email-agent", ["email:draft"]);
    const r = await get(net, { authorization: `DPoP ${token}`, dpop: await net.assistantClient.dpopProof("GET", EVENTS, token) });
    expect(r.status).toBe(401);
  });

  it("returns 403 when the token lacks the endpoint's scope", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const r = await net.calendar.fetch(new Request(EVENTS, {
      method: "POST",
      headers: { authorization: `DPoP ${token}`, dpop: await net.assistantClient.dpopProof("POST", EVENTS, token), "content-type": "application/json" },
      body: JSON.stringify({ title: "x", start: "y" }),
    }));
    expect(r.status).toBe(403);
    expect(((await r.json()) as any).error).toBe("insufficient_scope");
  });

  it("rejects an expired token even though the AS signed it", async () => {
    const net = await buildNetwork();
    const real = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const old = Math.floor(Date.now() / 1000) - 3600;
    const expired = await new SignJWT({ ...decodeJwt(real), iat: old, nbf: old, exp: old + 300 })
      .setProtectedHeader(decodeProtectedHeader(real) as any)
      .sign(await importPrivateKey(net.as.privateJwk));
    const r = await get(net, { authorization: `DPoP ${expired}`, dpop: await net.assistantClient.dpopProof("GET", EVENTS, expired) });
    expect(r.status).toBe(401);
    expect(((await r.json()) as any).error_description).toMatch(/exp/);
  });

  it("rejects a token the caller minted for itself", async () => {
    const net = await buildNetwork();
    const real = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const selfKey = await generateAgentKey();
    const forged = await new SignJWT({ ...decodeJwt(real), scope: "calendar:read calendar:write" })
      .setProtectedHeader(decodeProtectedHeader(real) as any)
      .sign(await importPrivateKey(selfKey.privateJwk));
    const r = await get(net, { authorization: `DPoP ${forged}`, dpop: await net.assistantClient.dpopProof("GET", EVENTS, forged) });
    expect(r.status).toBe(401);
  });

  it("binds tokens to the RFC 7638 thumbprint of the caller's key", async () => {
    const net = await buildNetwork();
    const token = await net.assistantClient.getToken("calendar-agent", ["calendar:read"]);
    const proof = decodeProtectedHeader(await net.assistantClient.dpopProof("GET", EVENTS, token));
    expect((decodeJwt(token) as any).cnf.jkt).toBe(await thumbprint(proof.jwk as any));
  });
});
