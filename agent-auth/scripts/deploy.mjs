#!/usr/bin/env node
/**
 * Deploy all five Workers to your Cloudflare account, in dependency order
 * (a service binding's target should exist before the Worker that binds it).
 *
 * Two modes:
 *
 *   npm run deploy
 *     First-time setup from your machine. Deploys, then uploads each Worker's
 *     secrets (the agents' private keys) from its .dev.vars file.
 *
 *   npm run deploy -- --code-only
 *     What CI runs. Deploys code only, then *verifies* the secrets already
 *     exist and fails if any are missing. Worker secrets survive deploys, so
 *     the private keys never need to be copied into GitHub.
 *
 * The web UI's Cloudflare Access settings can come from the environment
 * (ACCESS_TEAM_DOMAIN, ACCESS_AUD) instead of being committed to wrangler.jsonc.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { root, runTool } from "./run-tool.mjs";
const codeOnly = process.argv.includes("--code-only");

// [directory, secrets the Worker needs]
const WORKERS = [
  ["workers/auth-server", ["SIGNING_KEY", "AGENT_PUBLIC_KEYS"]],
  ["workers/calendar-agent", []],
  ["workers/email-agent", []],
  ["workers/assistant", ["AGENT_PRIVATE_KEY"]],
  ["apps/web", ["AGENT_PRIVATE_KEY"]], // ALLOW_UNAUTHENTICATED_DEV is never uploaded
];

function parseDevVars(file) {
  const out = {};
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^([A-Z_]+)='(.*)'$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

const wrangler = (cwd, ...args) => runTool("wrangler", args, { cwd });

function uploadSecrets(cwd, names) {
  const devVars = join(cwd, ".dev.vars");
  if (!existsSync(devVars)) throw new Error(`${devVars} missing: run \`npm run keys\` first`);
  const all = parseDevVars(devVars);
  const secrets = Object.fromEntries(names.map((n) => [n, all[n]]));
  // `secret bulk` reads a JSON file; keep it in a private temp dir and delete it right after.
  const tmp = mkdtempSync(join(tmpdir(), "a2a-"));
  try {
    writeFileSync(join(tmp, "secrets.json"), JSON.stringify(secrets), { mode: 0o600 });
    wrangler(cwd, "secret", "bulk", join(tmp, "secrets.json"));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function verifySecrets(cwd, names) {
  const out = runTool("wrangler", ["secret", "list", "--format", "json"], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  const present = new Set(JSON.parse(out).map((s) => s.name));
  const missing = names.filter((n) => !present.has(n));
  if (missing.length) {
    throw new Error(
      `${cwd}: missing secrets ${missing.join(", ")}. Run \`npm run deploy\` once from your machine to set them.`,
    );
  }
}

for (const [dir, secretNames] of WORKERS) {
  const cwd = join(root, dir);
  console.log(`\n=== ${dir} ===`);
  const args = ["deploy"];
  if (dir === "apps/web") {
    runTool("vite", ["build"], { cwd });
    for (const name of ["ACCESS_TEAM_DOMAIN", "ACCESS_AUD"]) {
      if (process.env[name]) args.push("--var", `${name}:${process.env[name]}`);
    }
    if (!process.env.ACCESS_TEAM_DOMAIN || !process.env.ACCESS_AUD) {
      console.warn("note: ACCESS_TEAM_DOMAIN/ACCESS_AUD not set; using wrangler.jsonc (web fails closed if empty)");
    }
  }
  wrangler(cwd, ...args);

  if (secretNames.length) {
    if (codeOnly) verifySecrets(cwd, secretNames);
    else uploadSecrets(cwd, secretNames);
  }
}

if (!codeOnly) {
  console.log(`
Done. Last step: protect the web UI with Cloudflare Access.
  1. Zero Trust dashboard -> Access -> Applications -> Add -> Self-hosted,
     domain = your a2a-web workers.dev hostname, policy = your email.
  2. Copy the application's "Application Audience (AUD) Tag".
  3. Set ACCESS_TEAM_DOMAIN ("<team>.cloudflareaccess.com") and ACCESS_AUD,
     either in apps/web/wrangler.jsonc or as GitHub Actions variables, and deploy again.
Until then the web UI answers 503 (it fails closed).`);
}
