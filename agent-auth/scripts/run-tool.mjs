/**
 * Run a CLI installed in node_modules (wrangler, vite) without `npx`.
 *
 * Why not npx? On Windows, `npx` is a batch file (npx.cmd), and Node refuses
 * to start batch files without a shell (a security fix since Node 18.20/20.12),
 * so `execFileSync("npx", ...)` fails with ENOENT/EINVAL. Starting the tool's
 * own JavaScript entry point with the current Node binary works identically
 * on Windows, macOS and Linux, and needs no shell, so arguments are never
 * re-parsed by one.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function binPath(pkg, bin = pkg) {
  const dir = join(root, "node_modules", pkg);
  const manifest = join(dir, "package.json");
  if (!existsSync(manifest)) throw new Error(`${pkg} is not installed: run \`npm install\` in ${root}`);
  const { bin: bins } = JSON.parse(readFileSync(manifest, "utf8"));
  const rel = typeof bins === "string" ? bins : bins?.[bin];
  if (!rel) throw new Error(`${pkg} has no "${bin}" executable`);
  return join(dir, rel);
}

/** Run a package's CLI. `options` are passed to execFileSync (cwd, stdio, encoding...). */
export function runTool(pkg, args, options = {}) {
  return execFileSync(process.execPath, [binPath(pkg), ...args], { stdio: "inherit", ...options });
}
