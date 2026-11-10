import { createHash } from "node:crypto";
import { matchIgnoreRule } from "./ignore.js";

export const SEVERITIES = ["low", "medium", "high", "critical"];
const RANK = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const FAIL_ON = ["low", "medium", "high", "critical", "none"];

const rank = (severity) => RANK[String(severity).toLowerCase()] ?? 0;

/**
 * Findings of a scan response, each with its package, and ignored ones marked.
 * Findings the server did not mark but the local ignore list matches are
 * marked here, so ignoring works against servers without ignore support.
 */
export function analyze(response, rules) {
  const results = Array.isArray(response?.results) ? response.results : [];
  let issues = Array.isArray(response?.issues) ? response.issues : null;
  // Older servers' flattened issues lack the package: take them per package then
  if (!issues || issues.some((i) => !i.package_name)) {
    issues = results.flatMap((r) =>
      (r.issues || []).map((i) => ({ ...i, package_name: r.name, package_version: r.version }))
    );
  }

  const findings = issues.map((issue) => {
    if (issue.ignored) return issue;
    const rule = rules.length
      ? matchIgnoreRule(rules, issue.findingId, issue.package_name, issue.package_version)
      : undefined;
    if (!rule) return { ...issue, ignored: false };
    return { ...issue, ignored: true, ignoredBy: rule.target, ...(rule.reason ? { ignoreReason: rule.reason } : {}) };
  });

  const failed = results
    .filter((r) => r.riskLevel === "failed")
    .map((r) => ({ name: r.name, version: r.version, error: r.error || "could not be analyzed" }));
  const active = findings.filter((f) => !f.ignored);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, active.filter((f) => f.severity === s).length]));
  // Files listed in a package but not reviewed (too large, unsupported): the
  // package's verdict doesn't cover them
  const notReviewed = results.flatMap((r) =>
    (Array.isArray(r.notReviewed) ? r.notReviewed : []).map((f) => ({
      name: r.name,
      version: r.version,
      file: f.file,
      reason: f.reason || "Not reviewed",
    }))
  );

  return {
    response,
    findings,
    active,
    failed,
    notReviewed,
    counts,
    ignoredCount: findings.length - active.length,
    packagesScanned: response?.summary?.packagesScanned ?? results.length,
  };
}

/** The response with local ignore marks applied and its summary to match */
export function annotatedResponse(analysis) {
  const { response, findings, active } = analysis;
  return {
    ...response,
    issues: findings,
    summary: {
      ...response.summary,
      totalIssues: active.length,
      highSeverityCount: active.filter((f) => rank(f.severity) >= RANK.high).length,
      ignoredCount: analysis.ignoredCount,
      filesNotReviewed: response.summary?.filesNotReviewed ?? analysis.notReviewed.length,
    },
  };
}

/** "dist/huge.js (Not reviewed: file too large (3072KB > 1024KB))" grouped per package */
function notReviewedByPackage(notReviewed) {
  const groups = new Map();
  for (const f of notReviewed) {
    const key = `${f.name}@${f.version}`;
    if (!groups.has(key)) groups.set(key, { name: f.name, version: f.version, files: [] });
    groups.get(key).files.push(f);
  }
  return [...groups.values()];
}

/** Why the scan fails a build, or an empty list when it passes */
export function failureReasons(analysis, { failOn, allowFailed }) {
  const reasons = [];
  if (failOn !== "none") {
    const n = analysis.active.filter((f) => rank(f.severity) >= RANK[failOn]).length;
    if (n > 0) reasons.push(`${n} finding${n === 1 ? "" : "s"} at or above ${failOn}`);
  }
  if (!allowFailed && analysis.failed.length > 0) {
    const n = analysis.failed.length;
    reasons.push(`${n} package${n === 1 ? "" : "s"} could not be scanned`);
  }
  return reasons;
}

// ============================================================================
// Text report
// ============================================================================

function severityLabel(severity, c) {
  const s = String(severity).toUpperCase().padEnd(8);
  switch (String(severity).toLowerCase()) {
    case "critical":
      return c.bold(c.red(s));
    case "high":
      return c.red(s);
    case "medium":
      return c.yellow(s);
    default:
      return c.blue(s);
  }
}

const oneLine = (s, max) => {
  const flat = String(s ?? "").replace(/\s+/g, " ").trim();
  return flat.length > max ? flat.slice(0, max - 1) + "…" : flat;
};

function location(f) {
  if (!f.file_path) return "";
  return f.line_number ? `${f.file_path}:${f.line_number}` : f.file_path;
}

/** Findings grouped per package, worst package first */
function groupByPackage(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.package_name}@${f.package_version}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  return [...groups.entries()]
    .map(([key, items]) => ({
      key,
      items: items.sort((a, b) => rank(b.severity) - rank(a.severity)),
      worst: Math.max(...items.map((f) => rank(f.severity))),
    }))
    .sort((a, b) => b.worst - a.worst || a.key.localeCompare(b.key));
}

export function renderText(analysis, { c, verbose, showIgnored, minSeverity = "low", failOn, allowFailed, lockfileName, ignoreFile, url }) {
  const out = [];
  const { counts, failed } = analysis;
  const width = 100;

  const listed = showIgnored ? analysis.findings : analysis.active;
  const shown = listed.filter((f) => rank(f.severity) >= RANK[minSeverity]);
  const hidden = listed.length - shown.length;
  for (const group of groupByPackage(shown)) {
    out.push("");
    out.push(`${c.bold(group.key)}`);
    for (const f of group.items) {
      const id = f.findingId ? c.cyan(f.findingId) : c.gray("(no id)");
      const ignored = f.ignored ? c.gray(` [ignored${f.ignoreReason ? `: ${oneLine(f.ignoreReason, 60)}` : ""}]`) : "";
      out.push(`  ${severityLabel(f.severity, c)} ${id}  ${oneLine(f.title, width)}${ignored}`);
      // Some scanners repeat the title as the type
      const type = f.type && String(f.type).toLowerCase() !== String(f.title).toLowerCase() ? f.type : "";
      const where = [location(f), type].filter(Boolean).join("  ");
      if (where) out.push(`           ${c.gray(where)}`);
      if (f.description) {
        out.push(`           ${verbose ? String(f.description).trim() : oneLine(f.description, width + 40)}`);
      }
      if (verbose && f.code_snippet) {
        for (const line of String(f.code_snippet).split("\n").slice(0, 8)) {
          out.push(`           ${c.dim("│ " + line.slice(0, width + 20))}`);
        }
      }
      if (verbose && f.recommendation) out.push(`           ${c.green("Fix:")} ${String(f.recommendation).trim()}`);
    }
  }

  const { notReviewed } = analysis;
  if (notReviewed.length > 0) {
    out.push("");
    out.push(c.bold("Files not reviewed") + c.gray(" (not covered by the verdicts above)"));
    const limit = verbose ? Infinity : 10;
    let listedFiles = 0;
    for (const group of notReviewedByPackage(notReviewed)) {
      if (listedFiles >= limit) break;
      out.push(`  ${group.name}@${group.version}`);
      for (const f of group.files) {
        if (listedFiles++ >= limit) break;
        out.push(`    ${c.yellow("SKIPPED ")} ${f.file}  ${c.gray(oneLine(f.reason, width))}`);
      }
    }
    if (notReviewed.length > limit) out.push(c.gray(`  ... and ${notReviewed.length - limit} more (--verbose lists all)`));
  }

  if (failed.length > 0) {
    out.push("");
    out.push(c.bold(allowFailed ? "Not analyzed (allowed by --allow-failed)" : c.red("Not analyzed")));
    for (const p of failed) out.push(`  ${c.magenta("FAILED  ")} ${p.name}@${p.version}  ${c.gray(oneLine(p.error, width))}`);
  }

  out.push("");
  const parts = [...SEVERITIES]
    .reverse()
    .map((s) => {
      const text = `${counts[s]} ${s}`;
      return counts[s] === 0 ? c.gray(text) : s === "critical" || s === "high" ? c.red(text) : s === "medium" ? c.yellow(text) : text;
    });
  const extras = [];
  if (analysis.ignoredCount) extras.push(`${analysis.ignoredCount} ignored`);
  if (failed.length) extras.push(c.magenta(`${failed.length} failed`));
  const notReviewedCount = analysis.response?.summary?.filesNotReviewed ?? notReviewed.length;
  if (notReviewedCount) extras.push(c.yellow(`${notReviewedCount} file${notReviewedCount === 1 ? "" : "s"} not reviewed`));
  const cached = analysis.response.cached ? c.gray(" (all cached, free)") : "";
  out.push(
    `${c.bold("Scanned")} ${analysis.packagesScanned} packages from ${lockfileName}${cached}: ${parts.join(", ")}${extras.length ? " · " + extras.join(" · ") : ""}`
  );

  if (hidden > 0) {
    out.push(c.gray(`${hidden} finding${hidden === 1 ? "" : "s"} below ${minSeverity} not listed (--min-severity low lists them)`));
  }
  const reasons = failureReasons(analysis, { failOn, allowFailed });
  if (reasons.length > 0) {
    out.push(`${c.bold(c.red("FAIL"))} ${reasons.join("; ")}`);
  } else {
    const below = analysis.active.length > 0 ? ` (no findings at or above ${failOn})` : "";
    out.push(`${c.bold(c.green("PASS"))}${failOn === "none" && analysis.active.length ? " (--fail-on none)" : below}`);
  }
  if (analysis.active.length > 0) {
    out.push(
      c.gray(`After reviewing a finding, add its ID to ${ignoreFile} to stop it failing the build. Details: ${url}/packages`)
    );
  }
  return out.join("\n") + "\n";
}

// ============================================================================
// SARIF (GitHub code scanning)
// ============================================================================

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note" };
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" };

/** First line of the lockfile that mentions the package near its version */
function lockfileLine(lines, name, version) {
  const bare = String(name).replace(/^[a-z]+:/, "");
  let first = 0;
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes(bare)) continue;
    if (!first) first = i + 1;
    for (let j = i; j < Math.min(i + 6, lines.length); j++) {
      if (lines[j].includes(version)) return i + 1;
    }
  }
  return first || 1;
}

export function renderSarif(analysis, { lockfileUri, lockfileContent, version, url, allowFailed }) {
  const lines = String(lockfileContent).split("\n");
  const rules = [];
  const results = [];
  const loc = (name, ver) => [
    {
      physicalLocation: {
        artifactLocation: { uri: lockfileUri },
        region: { startLine: lockfileLine(lines, name, ver) },
      },
      logicalLocations: [{ name: `${name}@${ver}`, kind: "package" }],
    },
  ];

  // One rule per finding: GitHub shows one alert per rule and location, and a
  // finding ID is what users ignore
  analysis.findings.forEach((f) => {
    const severity = SARIF_LEVEL[f.severity] ? f.severity : "low";
    // Servers without finding IDs: a fingerprint of what identifies the finding
    const ruleId =
      f.findingId ||
      `X-${createHash("sha256").update([f.package_name, f.file_path, f.type, f.line_number].join("\0")).digest("hex").slice(0, 12)}`;
    if (!rules.some((r) => r.id === ruleId)) {
      rules.push({
        id: ruleId,
        name: String(f.type || "finding").replace(/[^A-Za-z0-9]+/g, "-"),
        shortDescription: { text: oneLine(f.title, 200) || ruleId },
        fullDescription: { text: oneLine(f.description || f.title, 1000) || ruleId },
        help: {
          text: [f.recommendation, `Ignore after review by adding ${ruleId} to .npm-scanner-ignore.`].filter(Boolean).join("\n\n"),
        },
        helpUri: `${url}/packages`,
        defaultConfiguration: { level: SARIF_LEVEL[severity] },
        properties: {
          tags: ["security", "supply-chain", ...(f.type ? [String(f.type)] : [])],
          "security-severity": SECURITY_SEVERITY[severity],
          precision: "medium",
        },
      });
    }
    const where = location(f);
    results.push({
      ruleId,
      level: SARIF_LEVEL[severity],
      message: {
        text: `${f.package_name}@${f.package_version}: ${oneLine(f.title, 300)}${where ? ` (in ${where})` : ""}. ${oneLine(f.description, 600)}`.trim(),
      },
      locations: loc(f.package_name, f.package_version),
      partialFingerprints: { "npmScannerFindingId/v1": ruleId },
      properties: {
        package: f.package_name,
        version: f.package_version,
        severity: f.severity,
        file: f.file_path ?? null,
        line: f.line_number ?? null,
      },
      ...(f.ignored
        ? { suppressions: [{ kind: "external", justification: f.ignoreReason || `Ignored by ${f.ignoredBy}` }] }
        : {}),
    });
  });

  if (analysis.failed.length > 0) {
    rules.push({
      id: "scan-failed",
      name: "scan-failed",
      shortDescription: { text: "Package could not be analyzed" },
      fullDescription: { text: "The scanner could not analyze this package (download error, model error or timeout). Treat it as unknown, not safe." },
      helpUri: `${url}/packages`,
      defaultConfiguration: { level: allowFailed ? "note" : "error" },
    });
    for (const p of analysis.failed) {
      results.push({
        ruleId: "scan-failed",
        level: allowFailed ? "note" : "error",
        message: { text: `${p.name}@${p.version} could not be analyzed: ${oneLine(p.error, 300)}` },
        locations: loc(p.name, p.version),
        partialFingerprints: { "npmScannerFindingId/v1": `failed:${p.name}@${p.version}` },
      });
    }
  }

  // Informational: files a package's verdict doesn't cover, one result per package
  if (analysis.notReviewed.length > 0) {
    rules.push({
      id: "file-not-reviewed",
      name: "file-not-reviewed",
      shortDescription: { text: "Files not reviewed" },
      fullDescription: { text: "Files of the package were listed but not reviewed (too large or an unsupported type). The package's verdict does not cover them." },
      helpUri: `${url}/methodology`,
      defaultConfiguration: { level: "note" },
    });
    for (const group of notReviewedByPackage(analysis.notReviewed)) {
      const files = group.files.map((f) => `${f.file} (${oneLine(f.reason, 120)})`);
      results.push({
        ruleId: "file-not-reviewed",
        level: "note",
        message: {
          text: `${group.name}@${group.version}: ${group.files.length} file${group.files.length === 1 ? "" : "s"} not reviewed: ${files.slice(0, 20).join(", ")}${files.length > 20 ? `, and ${files.length - 20} more` : ""}`,
        },
        locations: loc(group.name, group.version),
        partialFingerprints: { "npmScannerFindingId/v1": `not-reviewed:${group.name}@${group.version}` },
        properties: { package: group.name, version: group.version, files: group.files.map((f) => ({ file: f.file, reason: f.reason })) },
      });
    }
  }

  return (
    JSON.stringify(
      {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "togoder-scan", version, informationUri: url, rules } },
            results,
          },
        ],
      },
      null,
      2
    ) + "\n"
  );
}
