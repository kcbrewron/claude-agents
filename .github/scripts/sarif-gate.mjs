#!/usr/bin/env node
/**
 * Fail CI when CodeQL reports a high or critical security finding.
 *
 * CodeQL uploads results to GitHub code scanning but does not fail the job
 * on its own. This reads the SARIF files the analyze step wrote and exits
 * non-zero if any unsuppressed result's rule has a `security-severity` at or
 * above the threshold. GitHub's scale (CVSS-style):
 *   critical >= 9.0, high >= 7.0, medium >= 4.0, low > 0
 *
 *   node sarif-gate.mjs <sarif-dir> [threshold=7.0]
 */
import { appendFileSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const [dir, thresholdArg = "7.0"] = process.argv.slice(2);
if (!dir) {
  console.error("usage: sarif-gate.mjs <sarif-dir> [threshold]");
  process.exit(2);
}
const threshold = Number(thresholdArg);

const label = (s) => (s >= 9 ? "CRITICAL" : s >= 7 ? "HIGH" : s >= 4 ? "MEDIUM" : "LOW");

const findings = [];
const files = readdirSync(dir).filter((f) => f.endsWith(".sarif"));
if (files.length === 0) {
  // No results file means the analysis didn't run: never treat that as a pass.
  console.error(`no .sarif files in ${dir}`);
  process.exit(2);
}

for (const file of files) {
  const sarif = JSON.parse(readFileSync(join(dir, file), "utf8"));
  for (const run of sarif.runs ?? []) {
    const rules = [
      ...(run.tool?.driver?.rules ?? []),
      ...(run.tool?.extensions ?? []).flatMap((e) => e.rules ?? []),
    ];
    const severity = new Map(rules.map((r) => [r.id, Number(r.properties?.["security-severity"] ?? 0)]));
    for (const result of run.results ?? []) {
      if ((result.suppressions ?? []).length > 0) continue;
      const ruleId = result.ruleId ?? result.rule?.id;
      const score = severity.get(ruleId) ?? 0;
      if (score < threshold) continue;
      const loc = result.locations?.[0]?.physicalLocation;
      findings.push({
        level: label(score),
        score,
        ruleId,
        where: `${loc?.artifactLocation?.uri ?? "?"}:${loc?.region?.startLine ?? "?"}`,
        message: result.message?.text ?? "",
      });
    }
  }
}

const summary = process.env.GITHUB_STEP_SUMMARY;
if (findings.length === 0) {
  console.log(`CodeQL: no findings with security-severity >= ${threshold}`);
  if (summary) appendFileSync(summary, `### CodeQL gate\nNo high or critical findings.\n`);
  process.exit(0);
}

findings.sort((a, b) => b.score - a.score);
for (const f of findings) {
  // ::error annotations show up on the PR's Files tab.
  console.log(`::error title=CodeQL ${f.level} (${f.score}) ${f.ruleId}::${f.where} ${f.message}`);
}
if (summary) {
  const rows = findings.map((f) => `| ${f.level} | ${f.score} | \`${f.ruleId}\` | \`${f.where}\` |`).join("\n");
  appendFileSync(summary, `### CodeQL gate: ${findings.length} blocking finding(s)\n| Level | Score | Rule | Location |\n|---|---|---|---|\n${rows}\n`);
}
process.exit(1);
