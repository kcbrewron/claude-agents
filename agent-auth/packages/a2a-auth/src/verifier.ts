/**
 * What an agent does when another agent calls it.
 *
 * For every request we answer three questions, in order:
 *
 *   1. Is the access token genuine?       signed by the AS, right issuer,
 *                                         addressed to *me* (aud), not expired
 *   2. Is the caller the token's owner?   DPoP proof signed by the key named in
 *                                         the token's cnf.jkt, for this exact
 *                                         method + URL, fresh, never seen before
 *   3. Is the caller allowed to do this?  the token carries the scope this
 *                                         endpoint requires
 *
 * Usage in a Hono agent:
 *
 *   app.get("/events", requireAgent(verifierFromEnv, "calendar:read"), (c) => {
 *     const caller = c.get("caller");  // { agentId, scopes }
 *   });
 */
import type { MiddlewareHandler } from "hono";
import { decodeProtectedHeader, errors, jwtVerify, type JWK } from "jose";
import { accessTokenHash, type Fetcher } from "./client";
import { ALG, importPublicKey, thumbprint } from "./keys";
import type { ReplayStore } from "./replay";

export interface Caller {
  agentId: string;
  scopes: Set<string>;
}

export interface VerifierOptions {
  /** This agent's id: tokens must be addressed to it. */
  audience: string;
  /** This agent's logical base URL, used to check the DPoP proof's htu. */
  selfUrl: string;
  issuer: string;
  /** Binding to the authorization server, used to fetch its JWKS. */
  auth: Fetcher;
  replay: ReplayStore;
  maxProofAgeSeconds?: number;
  clockSkewSeconds?: number;
}

export class AgentAuthError extends Error {
  constructor(
    readonly status: 401 | 403,
    readonly code: "invalid_token" | "insufficient_scope",
    message: string,
  ) {
    super(message);
  }
}

const unauthorized = (msg: string) => new AgentAuthError(401, "invalid_token", msg);

// ---- AS public keys (JWKS), cached per isolate ---------------------------
// Refetch on an unknown kid (that's how key rotation is picked up), but not
// more than once every 30s, so junk tokens can't make us hammer the AS.
const JWKS_MIN_REFRESH_MS = 30_000;
const jwksCache = new Map<string, { keys: Map<string, JWK>; fetchedAt: number }>();

async function issuerKey(opts: VerifierOptions, kid: string | undefined) {
  let entry = jwksCache.get(opts.issuer);
  if (kid && !entry?.keys.has(kid) && Date.now() - (entry?.fetchedAt ?? 0) > JWKS_MIN_REFRESH_MS) {
    const resp = await opts.auth.fetch(new Request(`${opts.issuer}/.well-known/jwks.json`));
    if (!resp.ok) throw unauthorized("could not fetch issuer keys");
    const { keys } = (await resp.json()) as { keys: JWK[] };
    entry = { keys: new Map(keys.map((k) => [k.kid!, k])), fetchedAt: Date.now() };
    jwksCache.set(opts.issuer, entry);
  }
  const jwk = kid ? entry?.keys.get(kid) : undefined;
  if (!jwk) throw unauthorized("unknown signing key");
  return importPublicKey(jwk);
}

/** For tests: forget cached issuer keys. */
export function clearJwksCache() {
  jwksCache.clear();
}

function describe(e: unknown): string {
  if (e instanceof errors.JOSEError) return e.message;
  return e instanceof Error ? e.message : String(e);
}

export async function verifyAgentRequest(req: Request, opts: VerifierOptions): Promise<Caller> {
  const maxAge = opts.maxProofAgeSeconds ?? 60;
  const skew = opts.clockSkewSeconds ?? 30;

  // ---- 1. the access token ------------------------------------------------
  const [scheme, token] = (req.headers.get("authorization") ?? "").split(" ", 2);
  if (scheme?.toLowerCase() !== "dpop" || !token) {
    // Plain "Bearer" is refused: our tokens are only valid with a proof.
    throw unauthorized("expected 'Authorization: DPoP <token>'");
  }
  let claims;
  try {
    const { kid } = decodeProtectedHeader(token);
    ({ payload: claims } = await jwtVerify(token, await issuerKey(opts, kid), {
      algorithms: [ALG], // never let the token pick its own algorithm
      typ: "at+jwt",
      issuer: opts.issuer,
      audience: opts.audience, // a token minted for another agent is useless here
      clockTolerance: skew,
      requiredClaims: ["sub", "exp", "iat", "jti", "cnf"],
    }));
  } catch (e) {
    if (e instanceof AgentAuthError) throw e;
    throw unauthorized(`access token rejected: ${describe(e)}`);
  }

  // ---- 2. the DPoP proof of possession -------------------------------------
  const proof = req.headers.get("dpop");
  if (!proof) throw unauthorized("missing DPoP proof");
  let proofClaims;
  try {
    const header = decodeProtectedHeader(proof);
    const jwk = header.jwk as JWK | undefined;
    if (!jwk) throw unauthorized("DPoP proof has no jwk");
    // Is the key that signed this proof the one the token is bound to?
    const bound = (claims.cnf as { jkt?: string } | undefined)?.jkt;
    if ((await thumbprint(jwk)) !== bound) throw unauthorized("DPoP key does not match token binding");
    ({ payload: proofClaims } = await jwtVerify(proof, await importPublicKey(jwk), {
      algorithms: [ALG],
      typ: "dpop+jwt",
      clockTolerance: skew,
      maxTokenAge: maxAge,
      requiredClaims: ["jti", "htm", "htu", "iat", "ath"],
    }));
  } catch (e) {
    if (e instanceof AgentAuthError) throw e;
    throw unauthorized(`DPoP proof rejected: ${describe(e)}`);
  }

  // Compare against our *configured* URL, not the incoming Host header, so a
  // proxy in front of us (or a spoofed Host) can't break or bypass the check.
  const expectedHtu = opts.selfUrl + new URL(req.url).pathname;
  if (proofClaims.htm !== req.method || proofClaims.htu !== expectedHtu) {
    throw unauthorized("DPoP proof is for a different request");
  }
  if (proofClaims.ath !== (await accessTokenHash(token))) {
    throw unauthorized("DPoP proof is for a different access token");
  }
  const expiresAt = (proofClaims.iat as number) + maxAge + skew;
  if (!(await opts.replay.checkAndStore(proofClaims.jti as string, expiresAt))) {
    throw unauthorized("DPoP proof replayed");
  }

  return {
    agentId: claims.sub!,
    scopes: new Set(String(claims.scope ?? "").split(" ").filter(Boolean)),
  };
}

export type AgentVariables = { caller: Caller };

/**
 * Hono middleware: authenticate the calling agent and demand these scopes.
 * `options` is a function because bindings (c.env) only exist per request.
 */
export function requireAgent<B extends object>(
  options: (env: B) => VerifierOptions,
  ...scopes: string[]
): MiddlewareHandler<{ Bindings: B; Variables: AgentVariables }> {
  return async (c, next) => {
    try {
      const caller = await verifyAgentRequest(c.req.raw, options(c.env));
      const missing = scopes.filter((s) => !caller.scopes.has(s));
      if (missing.length) {
        throw new AgentAuthError(403, "insufficient_scope", `needs ${missing.join(" ")}`);
      }
      c.set("caller", caller);
    } catch (e) {
      if (!(e instanceof AgentAuthError)) throw e;
      // Header values can't safely carry arbitrary error text (quotes, control chars).
      const desc = e.message.replace(/[^\x20-\x7e]|"/g, "'");
      c.header("WWW-Authenticate", `DPoP algs="${ALG}", error="${e.code}", error_description="${desc}"`);
      return c.json({ error: e.code, error_description: e.message }, e.status);
    }
    await next();
  };
}
