#!/usr/bin/env node
/**
 * Run all five Workers locally in one `wrangler dev` process. Service
 * bindings, Durable Objects and KV are simulated by workerd (the same runtime
 * Cloudflare uses in production). Workers AI always runs on Cloudflare, so
 * run `npx wrangler login` first for the assistant's model calls.
 *
 * The first config is the one served at http://localhost:8787: the web UI.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { root, runTool } from "./run-tool.mjs";

if (!existsSync(join(root, "apps/web/.dev.vars"))) {
  execFileSync(process.execPath, [join(root, "scripts/gen-keys.mjs")], { stdio: "inherit" });
}
runTool("vite", ["build"], { cwd: join(root, "apps/web") });

const configs = [
  "apps/web/wrangler.jsonc",
  "workers/assistant/wrangler.jsonc",
  "workers/auth-server/wrangler.jsonc",
  "workers/calendar-agent/wrangler.jsonc",
  "workers/email-agent/wrangler.jsonc",
];
runTool("wrangler", ["dev", ...configs.flatMap((c) => ["-c", c]), ...process.argv.slice(2)], { cwd: root });
