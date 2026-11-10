import { test } from "node:test";
import assert from "node:assert/strict";
import { formatIgnoreRules, matchIgnoreRule, parseIgnoreText } from "../lib/ignore.js";
import { analyze, annotatedResponse, failureReasons, renderSarif, renderText } from "../lib/report.js";
import { colorsFor } from "../lib/ui.js";

const ID_A = "NPS-3F9A0C1B2D4E";
const ID_B = "NPS-0811DA3A5FA0";

const response = {
  status: "completed",
  cached: false,
  results: [
    { name: "left-pad", version: "1.3.0", riskLevel: "high", issues: [] },
    { name: "@scope/pkg", version: "2.0.0", riskLevel: "low", issues: [] },
    { name: "broken", version: "0.0.1", riskLevel: "failed", issues: [], error: "Scanner timed out" },
  ],
  issues: [
    { findingId: ID_A, severity: "high", type: "network", title: "Fetches code", file_path: "a.js", line_number: 3, package_name: "left-pad", package_version: "1.3.0" },
    { findingId: ID_B, severity: "low", type: "fs", title: "Reads home", file_path: "b.js", package_name: "@scope/pkg", package_version: "2.0.0" },
  ],
  summary: { packagesScanned: 3, packagesFailed: 1, totalIssues: 2, highSeverityCount: 1 },
};

test("parses ignore entries like the server", () => {
  const { rules, errors } = parseIgnoreText(
    [`# comment`, `${ID_A.toLowerCase()} # reviewed`, `${ID_B}@2.0.0`, `@scope/pkg@2.0.0`, `left-pad`, `NPS-12`, `a b`, `x@`].join("\n")
  );
  assert.deepEqual(
    rules.map((r) => r.target),
    [ID_A, `${ID_B}@2.0.0`, "@scope/pkg@2.0.0", "left-pad"]
  );
  assert.equal(rules[0].reason, "reviewed");
  assert.equal(rules[2].packageName, "@scope/pkg");
  assert.equal(rules[2].version, "2.0.0");
  assert.equal(errors.length, 3);
  assert.match(errors[0], /:6: /);
  assert.equal(formatIgnoreRules(rules.slice(0, 2)), `${ID_A} # reviewed\n${ID_B}@2.0.0`);
});

test("most specific rule wins", () => {
  const { rules } = parseIgnoreText(`left-pad\n${ID_A}@1.3.0 # exact`);
  assert.equal(matchIgnoreRule(rules, ID_A, "left-pad", "1.3.0").reason, "exact");
  assert.equal(matchIgnoreRule(rules, ID_A, "left-pad", "1.4.0").target, "left-pad");
  assert.equal(matchIgnoreRule(rules, ID_B, "other", "1.3.0"), undefined);
});

test("fails on findings at or above --fail-on and on failed packages", () => {
  const a = analyze(response, []);
  assert.deepEqual(failureReasons(a, { failOn: "high", allowFailed: false }), [
    "1 finding at or above high",
    "1 package could not be scanned",
  ]);
  assert.deepEqual(failureReasons(a, { failOn: "critical", allowFailed: true }), []);
  assert.equal(failureReasons(a, { failOn: "low", allowFailed: true }).length, 1);
  assert.deepEqual(failureReasons(a, { failOn: "none", allowFailed: true }), []);
});

test("ignores findings client-side when the server did not", () => {
  const a = analyze(response, parseIgnoreText(`${ID_A} # ok`).rules);
  assert.equal(a.ignoredCount, 1);
  assert.deepEqual(failureReasons(a, { failOn: "high", allowFailed: true }), []);
  const annotated = annotatedResponse(a);
  assert.equal(annotated.summary.highSeverityCount, 0);
  assert.equal(annotated.summary.ignoredCount, 1);
  assert.equal(annotated.issues[0].ignoreReason, "ok");
});

test("keeps the server's ignore marks", () => {
  const marked = { ...response, issues: response.issues.map((i) => ({ ...i, ignored: i.findingId === ID_A, ignoredBy: ID_A })) };
  assert.equal(analyze(marked, []).ignoredCount, 1);
});

test("takes packages from results when issues lack them", () => {
  const legacy = {
    results: [{ name: "x", version: "1.0.0", riskLevel: "high", issues: [{ severity: "high", title: "t" }] }],
    issues: [{ severity: "high", title: "t" }],
  };
  const a = analyze(legacy, parseIgnoreText("x").rules);
  assert.equal(a.findings[0].package_name, "x");
  assert.equal(a.ignoredCount, 1);
});

test("renders text and SARIF", () => {
  const a = analyze(response, []);
  const text = renderText(a, { c: colorsFor({}, true), minSeverity: "medium", failOn: "high", allowFailed: false, lockfileName: "package-lock.json", ignoreFile: ".npm-scanner-ignore", url: "https://x" });
  assert.match(text, new RegExp(ID_A));
  assert.doesNotMatch(text, new RegExp(ID_B));
  assert.match(text, /FAIL/);
  assert.match(text, /broken@0\.0\.1/);

  const lock = `{\n  "packages": {\n    "node_modules/left-pad": {\n      "version": "1.3.0"\n    }\n  }\n}`;
  const sarif = JSON.parse(renderSarif(a, { lockfileUri: "package-lock.json", lockfileContent: lock, version: "0", url: "https://x", allowFailed: false }));
  const results = sarif.runs[0].results;
  assert.equal(results.length, 3);
  assert.equal(results[0].ruleId, ID_A);
  assert.equal(results[0].level, "error");
  assert.equal(results[0].locations[0].physicalLocation.region.startLine, 3);
  assert.equal(results[2].ruleId, "scan-failed");
});

test("reports files that were not reviewed in text, JSON and SARIF", () => {
  const withSkips = {
    ...response,
    results: response.results.map((r) =>
      r.name === "left-pad"
        ? { ...r, notReviewed: [{ file: "dist/huge.js", reason: "Not reviewed: file too large (3072KB > 1024KB)" }, { file: "notes.txt", reason: "Not reviewed: unsupported file type" }] }
        : r
    ),
    summary: { ...response.summary, filesNotReviewed: 2 },
  };
  const a = analyze(withSkips, []);
  assert.equal(a.notReviewed.length, 2);
  assert.deepEqual(a.notReviewed[0], { name: "left-pad", version: "1.3.0", file: "dist/huge.js", reason: "Not reviewed: file too large (3072KB > 1024KB)" });
  // not reviewed is informational: it never fails the build by itself
  assert.deepEqual(failureReasons(a, { failOn: "critical", allowFailed: true }), []);

  const text = renderText(a, { c: colorsFor({}, true), minSeverity: "low", failOn: "critical", allowFailed: true, lockfileName: "package-lock.json", ignoreFile: ".npm-scanner-ignore", url: "https://x" });
  assert.match(text, /Files not reviewed/);
  assert.match(text, /dist\/huge\.js .*file too large/);
  assert.match(text, /2 files not reviewed/);
  assert.match(text, /PASS/);

  assert.equal(annotatedResponse(a).summary.filesNotReviewed, 2);
  assert.equal(annotatedResponse(a).results[0].notReviewed.length, 2);
  // older servers without the summary count: counted from the results
  const { filesNotReviewed: _drop, ...older } = withSkips.summary;
  assert.equal(annotatedResponse(analyze({ ...withSkips, summary: older }, [])).summary.filesNotReviewed, 2);

  const sarif = JSON.parse(renderSarif(a, { lockfileUri: "package-lock.json", lockfileContent: "{}", version: "0", url: "https://x", allowFailed: true }));
  const note = sarif.runs[0].results.find((r) => r.ruleId === "file-not-reviewed");
  assert.equal(note.level, "note");
  assert.match(note.message.text, /left-pad@1\.3\.0: 2 files not reviewed: dist\/huge\.js/);
  assert.ok(sarif.runs[0].tool.driver.rules.some((r) => r.id === "file-not-reviewed"));
});

test("no not-reviewed section when every file was reviewed", () => {
  const a = analyze(response, []);
  assert.equal(a.notReviewed.length, 0);
  const text = renderText(a, { c: colorsFor({}, true), minSeverity: "low", failOn: "high", allowFailed: false, lockfileName: "package-lock.json", ignoreFile: ".npm-scanner-ignore", url: "https://x" });
  assert.doesNotMatch(text, /not reviewed/i);
  const sarif = JSON.parse(renderSarif(a, { lockfileUri: "package-lock.json", lockfileContent: "{}", version: "0", url: "https://x", allowFailed: false }));
  assert.ok(!sarif.runs[0].results.some((r) => r.ruleId === "file-not-reviewed"));
});
