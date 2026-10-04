/**
 * Baseline HTTP hardening shared by every Hono agent.
 *
 *   - Security headers: these agents only ever return JSON to other Workers,
 *     so the CSP forbids everything (`default-src 'none'`) and framing.
 *   - Cache-Control: no-store unless a route opts in. Tokens and per-user data
 *     must never be stored by a cache along the way.
 *   - A body size limit, so oversized payloads are rejected before parsing.
 *   - JSON 404s and a generic 500 that logs details instead of returning them.
 */
import type { Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { secureHeaders } from "hono/secure-headers";

export const MAX_BODY_BYTES = 64 * 1024;

/** Generic 500: details go to Workers Logs, never to the caller. */
export function internalError(err: unknown, c: Context) {
  console.error("unhandled error", err);
  return c.json({ error: "server_error", error_description: "internal error" }, 500);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function harden<A extends Hono<any>>(app: A, maxBodyBytes = MAX_BODY_BYTES): A {
  app.use(
    "*",
    secureHeaders({
      contentSecurityPolicy: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
      strictTransportSecurity: "max-age=63072000; includeSubDomains",
      referrerPolicy: "no-referrer",
      crossOriginResourcePolicy: "same-origin",
    }),
  );
  app.use("*", async (c, next) => {
    await next();
    if (!c.res.headers.has("Cache-Control")) c.res.headers.set("Cache-Control", "no-store");
  });
  app.use(
    "*",
    bodyLimit({
      maxSize: maxBodyBytes,
      onError: (c) => c.json({ error: "invalid_request", error_description: "request body too large" }, 413),
    }),
  );
  app.notFound((c) => c.json({ error: "not_found" }, 404));
  app.onError(internalError);
  return app;
}
