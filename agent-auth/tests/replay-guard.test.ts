/** The ReplayGuard Durable Object, with a fake of its storage API. */
import { describe, expect, it } from "vitest";
import { MemoryReplayStore } from "@agent-auth/a2a";
import { ReplayGuard } from "../packages/a2a-auth/src/replay-do";

class FakeStorage {
  data = new Map<string, number>();
  alarm: number | null = null;
  async get(key: string) {
    return this.data.get(key);
  }
  async put(key: string, value: number) {
    this.data.set(key, value);
  }
  async list({ prefix }: { prefix: string }) {
    return new Map([...this.data].filter(([k]) => k.startsWith(prefix)));
  }
  async delete(keys: string[]) {
    keys.forEach((k) => this.data.delete(k));
    return keys.length;
  }
  async getAlarm() {
    return this.alarm;
  }
  async setAlarm(at: number) {
    this.alarm = at;
  }
}

const now = () => Date.now() / 1000;

function guard() {
  const storage = new FakeStorage();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return { storage, guard: new ReplayGuard({ storage } as any, {}) };
}

describe("ReplayGuard Durable Object", () => {
  it("accepts a jti once and rejects it after that", async () => {
    const { guard: g } = guard();
    expect(await g.checkAndStore("a", now() + 60)).toBe(true);
    expect(await g.checkAndStore("a", now() + 60)).toBe(false);
    expect(await g.checkAndStore("b", now() + 60)).toBe(true);
  });

  it("schedules a cleanup alarm only once", async () => {
    const { guard: g, storage } = guard();
    await g.checkAndStore("a", now() + 60);
    const first = storage.alarm;
    expect(first).not.toBeNull();
    await g.checkAndStore("b", now() + 60);
    expect(storage.alarm).toBe(first);
  });

  it("cleans up expired entries and re-arms while entries remain", async () => {
    const { guard: g, storage } = guard();
    await g.checkAndStore("old", now() - 1);
    await g.checkAndStore("fresh", now() + 600);
    storage.alarm = null;
    await g.alarm();
    expect([...storage.data.keys()]).toEqual(["jti:fresh"]);
    expect(storage.alarm).not.toBeNull();
  });

  it("stops re-arming once everything has expired", async () => {
    const { guard: g, storage } = guard();
    for (let i = 0; i < 200; i++) await g.checkAndStore(`old-${i}`, now() - 1); // > 128: batched deletes
    storage.alarm = null;
    await g.alarm();
    expect(storage.data.size).toBe(0);
    expect(storage.alarm).toBeNull();
  });
});

describe("MemoryReplayStore", () => {
  it("forgets entries after they expire", async () => {
    const store = new MemoryReplayStore();
    expect(await store.checkAndStore("x", now() - 1)).toBe(true);
    // Expired, so purged on the next call and accepted again.
    expect(await store.checkAndStore("x", now() + 60)).toBe(true);
    expect(await store.checkAndStore("x", now() + 60)).toBe(false);
  });
});
