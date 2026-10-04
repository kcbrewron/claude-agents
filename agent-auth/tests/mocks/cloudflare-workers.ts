/**
 * Stand-in for the `cloudflare:workers` runtime module, which only exists
 * inside workerd. Tests set fields on `env` to play the part of bindings.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const env: Record<string, any> = {};

export class DurableObject<Env = unknown> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(readonly ctx: any, readonly env: Env) {}
}
