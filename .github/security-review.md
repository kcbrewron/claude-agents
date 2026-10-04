# Security review instructions

You are reviewing `agent-auth/`, a personal assistant built from five
Cloudflare Workers that authenticate each other with OAuth 2.0
(`private_key_jwt`), audience- and scope-limited JWT access tokens, and DPoP.
Your job is to find real, exploitable problems, not style issues.

## The system's trust boundaries

| Boundary | Who is on the other side | Expected control |
|---|---|---|
| Internet → `apps/web` | Anyone | Cloudflare Access JWT verified in `apps/web/src/hooks.server.ts` on **every** request; fails closed (503) when Access isn't configured |
| `web` → `assistant` | The web-ui agent | Token for `aud=assistant`, `scope=assistant:chat`, plus a DPoP proof |
| `assistant` → `calendar-agent` / `email-agent` | The assistant agent | Token for that one audience with the minimum scope, plus a DPoP proof |
| Any agent → `auth-server /token` | Any Worker with a binding | Signed client assertion verified against the registered public key; policy in `workers/auth-server/policy.json` |
| Workers AI → `assistant` | **Untrusted** model output (it can be prompt-injected) | Tool names and arguments validated in `workers/assistant/src/tools.ts`; permission decided by the auth server, never by the model |
| Agent data (KV, tool results) → model | **Untrusted** content | Treated as data, never as instructions |

Only `apps/web` may be publicly reachable. Every other Worker must keep
`"workers_dev": false` and `"preview_urls": false` in its `wrangler.jsonc`.

## Checklist

### 1. No unauthenticated access to exposed endpoints
- Every route in every Hono app (`workers/*/src/app.ts`) must use `requireAgent(...)`,
  except these intentionally public ones: `GET /.well-known/jwks.json`,
  `GET /.well-known/oauth-authorization-server`, `POST /token` (which authenticates the client itself).
- Every SvelteKit route and endpoint in `apps/web/src/routes` must be covered by the
  `handle` hook's authentication. Look for anything that bypasses it.
- The dev bypass (`ALLOW_UNAUTHENTICATED_DEV`) must require a localhost URL and must
  never be deployed (`scripts/deploy.mjs`).
- Check that `wrangler.jsonc` exposure settings match the table above.

### 2. Token and key handling
- Signature algorithms pinned server-side (`EdDSA`); no `alg` taken from the token.
- `iss`, `aud`, `exp`, `typ` and the scopes verified; DPoP `htm`, `htu`, `ath`, `iat`
  and `jti` verified; replay protection uses the Durable Object, not memory or KV.
- Private keys only in Worker secrets or gitignored `.dev.vars`; never committed,
  logged, or returned in a response. The JWKS endpoint must publish public parts only.

### 3. Input validation
- Every request body is parsed with a schema (zod) or explicit checks, with length
  and size limits; the body size limit from `harden()` applies.
- Model-supplied tool arguments are validated before any agent call.
- Values used in KV keys, headers, or log lines can't inject structure (e.g. CRLF, `:`).

### 4. Security and cache headers
- `apps/web`: CSP (configured in `apps/web/vite.config.ts`), `frame-ancestors 'none'`,
  HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and
  `Cache-Control: private, no-store` on every dynamic response, including errors.
- Hono agents: headers from `harden()` and `Cache-Control: no-store`, except the
  public JWKS and discovery documents, which may be cached briefly.
- Error responses must not leak stack traces, upstream error text, or secrets.

### 5. CI/CD (`.github/workflows`)
- Least-privilege `permissions`; no `pull_request_target`; no untrusted
  `${{ github.event.* }}` text interpolated directly into `run:` scripts.
- Deploy only from `main` after CI succeeds, for the commit that was tested.

## How to report

1. Verify each finding by reading the code. Show the concrete path an attacker
   would take. Do not report theoretical issues you can't tie to code.
2. Post **one** PR comment with `gh pr comment`, in this format:

   ```
   ## Security review
   **Result:** N finding(s) (C critical, H high, M medium, L low)  —or—  No findings.

   ### [SEVERITY] Short title
   - **Where:** `path/to/file.ts:LINE`
   - **Boundary:** which trust boundary from the table
   - **Exploit:** how it would be abused
   - **Fix:** the specific change
   ```
3. You may also add inline comments on specific lines for high or critical findings.
4. Skip style, naming, and formatting. If something is fine, don't mention it.
