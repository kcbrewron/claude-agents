/**
 * Replay protection.
 *
 * Client assertions and DPoP proofs are one-time messages carrying a unique
 * `jti`. If an attacker captures one and sends it again, we must have already
 * recorded that jti.
 *
 * On Workers, a plain in-memory Map doesn't work: requests are spread across
 * many isolates in many data centers, each with its own memory. Workers KV
 * doesn't work either, because it's eventually consistent and two replays
 * could both read "not seen". A Durable Object gives us a single, strongly
 * consistent place to record each jti (see replay-do.ts).
 */

export interface ReplayStore {
  /** Resolve true the first time a jti is seen, false on any replay. */
  checkAndStore(jti: string, expiresAt: number): Promise<boolean>;
}

/** The parts of a DurableObjectNamespace we use, so tests can pass a fake. */
export interface ReplayNamespace {
  idFromName(name: string): unknown;
  get(id: never): ReplayStore;
}

export function replayStore(ns: ReplayNamespace, scope: string): ReplayStore {
  return ns.get(ns.idFromName(scope) as never);
}

/** For tests and local experiments only: per-process memory. */
export class MemoryReplayStore implements ReplayStore {
  private seen = new Map<string, number>();

  async checkAndStore(jti: string, expiresAt: number): Promise<boolean> {
    const now = Date.now() / 1000;
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, expiresAt);
    return true;
  }
}
