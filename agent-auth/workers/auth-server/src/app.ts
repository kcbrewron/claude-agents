/**
 * The authorization server (AS): the one place that decides who may talk to whom.
 *
 * Flow for one token request (OAuth 2.0 client credentials + private_key_jwt):
 *
 *   1. The calling agent signs a short "client assertion" JWT with its private
 *      key (RFC 7523). No shared secret ever crosses the wire.
 *   2. We verify that signature against the agent's *registered* public key,
 *      so we know which agent is asking.
 *   3. We check policy.json: may this agent get these scopes at that target
 *      (the `resource` parameter, RFC 8707)?
 *   4. We issue a short-lived access token JWT (RFC 9068) signed with *our*
 *      key, with `aud` = the one target agent and `cnf.jkt` binding it to the
 *      caller's key (RFC 9449), so a stolen token is useless without that key.
 */
import { Hono } from "hono";
import { SignJWT, decodeJwt, errors, jwtVerify, type JWK } from "jose";
import {
  ALG,
  CLIENT_ASSERTION_TYPE,
  importPrivateKey,
  harden,
  importPublicKey,
  internalError,
  publicPart,
  replayStore,
  thumbprint,
  type ReplayNamespace,
} from "@agent-auth/a2a";
import policyFile from "../policy.json";

export type Env = {
  ISSUER: string;
  ACCESS_TOKEN_TTL?: string;
  SIGNING_KEY: string;
  AGENT_PUBLIC_KEYS: string;
  REPLAY: ReplayNamespace;
};

type Policy = Record<string, Record<string, string[]>>;
const POLICY = policyFile.agents as Policy;

const MAX_ASSERTION_LIFETIME_S = 60;
const CLOCK_SKEW_S = 30;

class OAuthError extends Error {
  constructor(
    readonly status: 400 | 401,
    readonly error: string,
    description: string,
  ) {
    super(description);
  }
}

export function createApp(policy: Policy = POLICY) {
  const app = harden(new Hono<{ Bindings: Env }>());

  // Errors in the RFC 6749 §5.2 JSON shape; token responses must never be cached.
  app.onError((err, c) => {
    if (!(err instanceof OAuthError)) return internalError(err, c);
    c.header("Cache-Control", "no-store");
    return c.json({ error: err.error, error_description: err.message }, err.status);
  });

  // Public keys and metadata are safe to cache briefly.
  const PUBLIC_CACHE = "public, max-age=300";

  app.get("/.well-known/oauth-authorization-server", (c) => {
    // RFC 8414 discovery document.
    c.header("Cache-Control", PUBLIC_CACHE);
    return c.json({
      issuer: c.env.ISSUER,
      token_endpoint: `${c.env.ISSUER}/token`,
      jwks_uri: `${c.env.ISSUER}/.well-known/jwks.json`,
      grant_types_supported: ["client_credentials"],
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      token_endpoint_auth_signing_alg_values_supported: [ALG],
      dpop_signing_alg_values_supported: [ALG],
    });
  });

  app.get("/.well-known/jwks.json", (c) => {
    // Agents fetch this to verify the tokens we sign. Public half only!
    const jwk = JSON.parse(c.env.SIGNING_KEY) as JWK;
    c.header("Cache-Control", PUBLIC_CACHE);
    return c.json({ keys: [{ ...publicPart(jwk), kid: jwk.kid, alg: ALG, use: "sig" }] });
  });

  app.post("/token", async (c) => {
    const form = await c.req.parseBody();
    const field = (name: string) => (typeof form[name] === "string" ? (form[name] as string) : undefined);

    if (field("grant_type") !== "client_credentials") {
      throw new OAuthError(400, "unsupported_grant_type", "only client_credentials is supported");
    }
    if (field("client_assertion_type") !== CLIENT_ASSERTION_TYPE || !field("client_assertion")) {
      throw new OAuthError(401, "invalid_client", "only private_key_jwt client auth is supported");
    }

    // ---- Authentication: who is asking? ----------------------------------
    const registry = JSON.parse(c.env.AGENT_PUBLIC_KEYS) as Record<string, JWK>;
    const assertion = field("client_assertion")!;
    let agentId: string;
    try {
      agentId = decodeJwt(assertion).iss ?? "";
    } catch {
      throw new OAuthError(401, "invalid_client", "malformed client assertion");
    }
    if (!Object.hasOwn(registry, agentId)) throw new OAuthError(401, "invalid_client", "unknown client");
    const clientId = field("client_id");
    if (clientId !== undefined && clientId !== agentId) {
      throw new OAuthError(401, "invalid_client", "client_id does not match assertion");
    }

    let claims;
    try {
      ({ payload: claims } = await jwtVerify(assertion, await importPublicKey(registry[agentId]), {
        algorithms: [ALG], // fixed server-side: blocks "alg: none" and algorithm confusion
        issuer: agentId,
        subject: agentId,
        // Our own issuer id, so an assertion made for another server can't be replayed here.
        audience: c.env.ISSUER,
        clockTolerance: CLOCK_SKEW_S,
        requiredClaims: ["exp", "iat", "jti"],
      }));
    } catch (e) {
      const why = e instanceof errors.JOSEError ? e.message : "invalid";
      throw new OAuthError(401, "invalid_client", `client assertion rejected: ${why}`);
    }
    if (claims.exp! - claims.iat! > MAX_ASSERTION_LIFETIME_S) {
      throw new OAuthError(401, "invalid_client", "client assertion lifetime too long");
    }
    const fresh = await replayStore(c.env.REPLAY, "client-assertions").checkAndStore(
      claims.jti!,
      claims.exp! + CLOCK_SKEW_S,
    );
    if (!fresh) throw new OAuthError(401, "invalid_client", "client assertion already used");

    // ---- Authorization: least privilege, deny by default -----------------
    const resource = field("resource") ?? "";
    const allowed = new Set(policy[agentId]?.[resource] ?? []);
    if (allowed.size === 0) throw new OAuthError(400, "invalid_target", `${agentId} may not call ${resource}`);
    const requested = [...new Set((field("scope") ?? "").split(" ").filter(Boolean))].sort();
    if (requested.length === 0) throw new OAuthError(400, "invalid_scope", "request at least one scope");
    const denied = requested.filter((s) => !allowed.has(s));
    if (denied.length) throw new OAuthError(400, "invalid_scope", `not permitted: ${denied.join(" ")}`);

    // ---- Issue the token ---------------------------------------------------
    const ttl = Number(c.env.ACCESS_TOKEN_TTL ?? 300);
    const signingJwk = JSON.parse(c.env.SIGNING_KEY) as JWK;
    const scope = requested.join(" ");
    const accessToken = await new SignJWT({
      client_id: agentId,
      scope,
      // Sender constraint: only the holder of the key with this thumbprint can use it.
      cnf: { jkt: await thumbprint(registry[agentId]) },
    })
      .setProtectedHeader({ alg: ALG, kid: signingJwk.kid, typ: "at+jwt" })
      .setIssuer(c.env.ISSUER)
      .setSubject(agentId)
      .setAudience(resource) // valid at exactly one agent
      .setIssuedAt()
      .setNotBefore("0s")
      .setExpirationTime(`${ttl}s`)
      .setJti(crypto.randomUUID())
      .sign(await importPrivateKey(signingJwk));

    c.header("Cache-Control", "no-store");
    return c.json({ access_token: accessToken, token_type: "DPoP", expires_in: ttl, scope });
  });

  return app;
}
