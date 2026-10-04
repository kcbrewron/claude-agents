#!/usr/bin/env node
/**
 * Step 1: give each calling agent, and the auth server, its own Ed25519 key.
 *
 * Writes a .dev.vars file per Worker. `wrangler dev` reads .dev.vars as
 * secrets locally, and `npm run deploy` uploads the same values as Worker
 * secrets. .dev.vars is gitignored: private keys must never be committed.
 *
 *   node scripts/gen-keys.mjs           create keys if missing
 *   node scripts/gen-keys.mjs --rotate  replace all keys
 */
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rotate = process.argv.includes("--rotate");

const files = {
  auth: join(root, "workers/auth-server/.dev.vars"),
  assistant: join(root, "workers/assistant/.dev.vars"),
  web: join(root, "apps/web/.dev.vars"),
};

if (!rotate && Object.values(files).every(existsSync)) {
  console.log("Keys already exist. Use --rotate to replace them.");
  process.exit(0);
}

async function newKey() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  const pub = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(pub);
  return {
    privateJwk: { ...(await exportJWK(privateKey)), kid, alg: "EdDSA" },
    publicJwk: { ...pub, kid, alg: "EdDSA", use: "sig" },
  };
}

const [authServer, assistant, webUi] = await Promise.all([newKey(), newKey(), newKey()]);

// .dev.vars uses dotenv syntax; JSON goes in single quotes.
const vars = (obj) =>
  Object.entries(obj)
    .map(([k, v]) => `${k}='${typeof v === "string" ? v : JSON.stringify(v)}'`)
    .join("\n") + "\n";

writeFileSync(
  files.auth,
  vars({
    SIGNING_KEY: authServer.privateJwk,
    // The registry: public keys only. These agents may ask for tokens.
    AGENT_PUBLIC_KEYS: { assistant: assistant.publicJwk, "web-ui": webUi.publicJwk },
  }),
  { mode: 0o600 },
);
writeFileSync(files.assistant, vars({ AGENT_PRIVATE_KEY: assistant.privateJwk }), { mode: 0o600 });
writeFileSync(
  files.web,
  vars({
    AGENT_PRIVATE_KEY: webUi.privateJwk,
    // Local only: skip Cloudflare Access. Never uploaded by deploy.mjs.
    ALLOW_UNAUTHENTICATED_DEV: "true",
  }),
  { mode: 0o600 },
);

console.log("Wrote:");
for (const f of Object.values(files)) console.log("  " + f.replace(root + "/", ""));
console.log(`\nauth-server key id: ${authServer.publicJwk.kid}`);
console.log(`assistant   key id: ${assistant.publicJwk.kid}`);
console.log(`web-ui      key id: ${webUi.publicJwk.kid}`);
