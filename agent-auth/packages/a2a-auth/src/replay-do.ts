/**
 * Durable Object that records seen jti values.
 *
 * Why this is race-free: a Durable Object processes events for one id in a
 * single thread, and its "input gate" holds back other incoming calls while a
 * storage operation is in flight. So the get-then-put below can't interleave
 * with another call checking the same jti.
 *
 * Each Worker exports this class and binds it as REPLAY. Old entries are
 * cleaned up by an alarm so storage stays small.
 */
import { DurableObject } from "cloudflare:workers";

const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

export class ReplayGuard extends DurableObject {
  async checkAndStore(jti: string, expiresAt: number): Promise<boolean> {
    const key = `jti:${jti}`;
    if ((await this.ctx.storage.get(key)) !== undefined) return false;
    await this.ctx.storage.put(key, expiresAt);
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + CLEANUP_INTERVAL_MS);
    }
    return true;
  }

  async alarm(): Promise<void> {
    const now = Date.now() / 1000;
    const entries = await this.ctx.storage.list<number>({ prefix: "jti:" });
    const expired = [...entries].filter(([, exp]) => exp < now).map(([k]) => k);
    // delete() accepts at most 128 keys per call.
    for (let i = 0; i < expired.length; i += 128) {
      await this.ctx.storage.delete(expired.slice(i, i + 128));
    }
    if (entries.size > expired.length) {
      await this.ctx.storage.setAlarm(Date.now() + CLEANUP_INTERVAL_MS);
    }
  }
}
