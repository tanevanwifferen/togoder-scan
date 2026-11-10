/**
 * Ignore lists, parsed and matched the same way as the server
 * (web-server/src/services/findings.ts), so they work against servers that
 * predate server-side ignoring too. One entry per line:
 *   NPS-XXXXXXXXXXXX            that finding, in any version
 *   NPS-XXXXXXXXXXXX@1.2.3      that finding, only in version 1.2.3
 *   name@1.2.3                  every finding of that package version
 *   name                        every finding of that package
 * Anything after "#" is a comment, kept as the reason.
 */

export const IGNORE_FILE = ".npm-scanner-ignore";
export const FINDING_ID_PATTERN = /^NPS-[0-9A-F]{12}$/;

function parseLine(line) {
  const hash = line.indexOf("#");
  const reason = hash >= 0 ? line.slice(hash + 1).trim() : "";
  const tokens = (hash >= 0 ? line.slice(0, hash) : line).trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return null;
  if (tokens.length > 1) {
    return `"${line.trim()}": one finding ID or package per line (put reasons after "#")`;
  }

  const target = tokens[0];
  const rule = { target, ...(reason ? { reason } : {}) };
  // Scoped npm names start with "@": the version separator is a later "@"
  const at = target.lastIndexOf("@");
  const [subject, version] = at > 0 ? [target.slice(0, at), target.slice(at + 1)] : [target, ""];
  if (at > 0 && !version) return `"${target}": missing version after "@"`;
  if (version) rule.version = version;

  if (/^NPS-/i.test(subject)) {
    const id = subject.toUpperCase();
    if (!FINDING_ID_PATTERN.test(id)) {
      return `"${target}": finding IDs look like NPS- followed by 12 hex characters`;
    }
    rule.findingId = id;
    rule.target = version ? `${id}@${version}` : id;
  } else {
    rule.packageName = subject;
  }
  return rule;
}

/** Rules and errors (with line numbers) of ignore-file text */
export function parseIgnoreText(text, source = IGNORE_FILE) {
  const rules = [];
  const errors = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const parsed = parseLine(line);
    if (typeof parsed === "string") errors.push(`${source}:${i + 1}: ${parsed}`);
    else if (parsed) rules.push(parsed);
  });
  return { rules, errors };
}

/** The ignore list as the server's `ignore` field expects it */
export function formatIgnoreRules(rules) {
  return rules
    .map((r) => (r.reason ? `${r.target} # ${r.reason.replace(/[\r\n]+/g, " ")}` : r.target))
    .join("\n");
}

/** The rule that ignores a finding, most specific first */
export function matchIgnoreRule(rules, findingId, name, version) {
  let best;
  let bestScore = -1;
  for (const r of rules) {
    const hit = (r.findingId ? r.findingId === findingId : r.packageName === name) && (!r.version || r.version === version);
    if (!hit) continue;
    const score = (r.findingId ? 2 : 0) + (r.version ? 1 : 0);
    if (score > bestScore) {
      best = r;
      bestScore = score;
    }
  }
  return best;
}
