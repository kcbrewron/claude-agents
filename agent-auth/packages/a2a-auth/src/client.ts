/**
 * What an agent does when it wants to call another agent.
 *
 *   getToken("calendar-agent", ["calendar:read"])
 *     -> signs a client assertion with our private key (RFC 7523) and POSTs it
 *        to the authorization server's /token endpoint
 *   request("calendar-agent", "GET", "/events", ["calendar:read"])
 *     -> sends  Authorization: DPoP <token>
 *               DPoP: <fresh proof JWT signed with our private key>
 *
 * Every call travels over a *service binding* (a Fetcher): Worker-to-Worker
 * inside Cloudflare, never over the public internet. The URL's hostname is
 * just a logical identifier; the binding decides where the request goes.
 */
import { SignJWT, base64url, type CryptoKey, type JWK } from "jose";
import { ALG, importPrivateKey, publicPart } from "./keys";

export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** Anything with a fetch(): a service binding, or globalThis in tests. */
export interface Fetcher {
  fetch(input: Request): Promise<Response>;
}

export interface ServiceTarget {
  url: string;
  fetcher: Fetcher;
}

export interface AgentClientOptions {
  agentId: string;
  privateJwk: JWK;
  issuer: string;
  auth: Fetcher;
  services: Record<string, ServiceTarget>;
}

export class TokenRequestError extends Error {
  constructor(
    readonly status: number,
    readonly body: { error?: string; error_description?: string },
  ) {
    super(`${status}: ${body.error}: ${body.error_description}`);
  }
}

/** The DPoP `ath` claim: ties a proof to one specific access token. */
export async function accessTokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return base64url.encode(new Uint8Array(digest));
}

// Refresh a little early so a token never expires mid-flight.
const REFRESH_MARGIN_S = 30;

export class AgentClient {
  private key: Promise<CryptoKey>;
  private tokens = new Map<string, { token: string; expiresAt: number }>();

  constructor(private readonly opts: AgentClientOptions) {
    this.key = importPrivateKey(opts.privateJwk);
  }

  /** Forget cached access tokens, e.g. after a key rotation. */
  clearTokens(): void {
    this.tokens.clear();
  }

  // -- step 1: prove who we are to the authorization server ----------------
  async clientAssertion(): Promise<string> {
    const { agentId, issuer, privateJwk } = this.opts;
    return new SignJWT({})
      .setProtectedHeader({ alg: ALG, kid: privateJwk.kid })
      .setIssuer(agentId)
      .setSubject(agentId)
      // The AS issuer identifier, so this assertion is useless at any other server.
      .setAudience(issuer)
      .setIssuedAt()
      .setExpirationTime("60s")
      .setJti(crypto.randomUUID())
      .sign(await this.key);
  }

  async getToken(audience: string, scopes: string[]): Promise<string> {
    const cacheKey = `${audience} ${[...scopes].sort().join(" ")}`;
    const cached = this.tokens.get(cacheKey);
    if (cached && cached.expiresAt - REFRESH_MARGIN_S > Date.now() / 1000) return cached.token;

    const resp = await this.opts.auth.fetch(
      new Request(`${this.opts.issuer}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: this.opts.agentId,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: await this.clientAssertion(),
          resource: audience,
          scope: scopes.join(" "),
        }),
      }),
    );
    const body = (await resp.json()) as Record<string, any>;
    if (!resp.ok) throw new TokenRequestError(resp.status, body);
    this.tokens.set(cacheKey, { token: body.access_token, expiresAt: Date.now() / 1000 + body.expires_in });
    return body.access_token;
  }

  // -- step 2: prove we hold the key the token is bound to -----------------
  async dpopProof(method: string, url: string, accessToken: string): Promise<string> {
    const htu = url.split("#")[0].split("?")[0];
    return new SignJWT({ htm: method.toUpperCase(), htu, ath: await accessTokenHash(accessToken) })
      .setProtectedHeader({ alg: ALG, typ: "dpop+jwt", jwk: publicPart(this.opts.privateJwk) })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(await this.key);
  }

  async request(
    audience: string,
    method: string,
    path: string,
    scopes: string[],
    body?: unknown,
  ): Promise<Response> {
    const target = this.opts.services[audience];
    if (!target) throw new Error(`no service binding for ${audience}`);
    const token = await this.getToken(audience, scopes);
    const url = target.url + path;
    const headers: Record<string, string> = {
      authorization: `DPoP ${token}`,
      dpop: await this.dpopProof(method, url, token),
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    return target.fetcher.fetch(
      new Request(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }),
    );
  }
}
