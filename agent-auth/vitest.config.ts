import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const path = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Every package must clear the bar on its own, so a well-tested package
// can't hide an untested one inside a healthy-looking overall number.
const BAR = { statements: 80, branches: 80, functions: 80, lines: 80 };

export default defineConfig({
  resolve: {
    alias: { "cloudflare:workers": path("./tests/mocks/cloudflare-workers.ts") },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "lcov"],
      include: ["packages/*/src/**/*.ts", "workers/*/src/**/*.ts", "apps/web/src/**/*.ts"],
      exclude: [
        "**/*.d.ts",
        // Two-line entry points that only wire modules together.
        "workers/*/src/index.ts",
        "packages/a2a-auth/src/index.ts",
        "apps/web/src/lib/index.ts",
      ],
      thresholds: {
        ...BAR,
        "packages/a2a-auth/src/**": BAR,
        "workers/auth-server/src/**": BAR,
        "workers/assistant/src/**": BAR,
        "workers/calendar-agent/src/**": BAR,
        "workers/email-agent/src/**": BAR,
        "apps/web/src/**": BAR,
      },
    },
  },
});
