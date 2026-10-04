#!/usr/bin/env node
/**
 * Deploy all five Workers to your Cloudflare account, in dependency order
 * (a service binding's target should exist before the Worker that binds it),
 * then upload each Worker's secrets from its .dev.vars file.
 *
 *   npx wrangler login     # once
 *   npm run keys           # once
 *   npm run deploy
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// [directory, secrets to upload from its .dev.vars]
const WORKERS = [
  ["workers/auth-server", ["SIGNING_KEY", "AGENT_PUBLIC_KEYS"]],
  ["workers/calendar-agent", []],
  ["workers/email-agent", []],
  ["workers/assistant", ["AGENT_PRIVATE_KEY"]],
  ["apps/web", ["AGENT_PRIVATE_KEY"]], // note: ALLOW_UNAUTHENTICATED_DEV is never uploaded
];

function parseDevVars(file) {
  const out = {};
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const m = line.match(/^([A-Z_]+)='(.*)'$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

const run = (cwd, ...args) => execFileSync("npx", ["wrangler", ...args], { cwd, stdio: "inherit" });

for (const [dir, secretNames] of WORKERS) {
  const cwd = join(root, dir);
  console.log(`\n=== ${dir} ===`);
  if (dir === "apps/web") execFileSync("npx", ["vite", "build"], { cwd, stdio: "inherit" });
  run(cwd, "deploy");

  if (secretNames.length) {
    const devVars = join(cwd, ".dev.vars");
    if (!existsSync(devVars)) throw new Error(`${devVars} missing: run \`npm run keys\` first`);
    const all = parseDevVars(devVars);
    const secrets = Object.fromEntries(secretNames.map((n) => [n, all[n]]));
    // `secret bulk` reads a JSON file; keep it in a private temp dir and delete it right after.
    const tmp = mkdtempSync(join(tmpdir(), "a2a-"));
    try {
      writeFileSync(join(tmp, "secrets.json"), JSON.stringify(secrets), { mode: 0o600 });
      run(cwd, "secret", "bulk", join(tmp, "secrets.json"));
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
}

console.log(`
Done. Last step: protect the web UI with Cloudflare Access.
  1. Zero Trust dashboard -> Access -> Applications -> Add -> Self-hosted,
     domain = your a2a-web workers.dev hostname, policy = your email.
  2. Copy the application's "Application Audience (AUD) Tag".
  3. In apps/web/wrangler.jsonc set ACCESS_TEAM_DOMAIN ("<team>.cloudflareaccess.com")
     and ACCESS_AUD, then run: cd apps/web && npx vite build && npx wrangler deploy
Until then the web UI answers 503 (it fails closed).`);
