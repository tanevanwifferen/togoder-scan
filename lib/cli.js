import { readFile, stat, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { ApiError, createClient, errorFrom, getQuote, runScan } from "./api.js";
import { configPath, readConfig, resolveSettings, updateConfig } from "./config.js";
import { formatIgnoreRules, IGNORE_FILE, parseIgnoreText } from "./ignore.js";
import { analyze, annotatedResponse, FAIL_ON, SEVERITIES, failureReasons, renderSarif, renderText } from "./report.js";
import { colorsFor, createProgress } from "./ui.js";

const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

export const EXIT = { OK: 0, FINDINGS: 1, ERROR: 2 };

// Lockfiles the server parses, in the order they are looked for
const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"];
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

const HELP = `togoder-scan ${VERSION}
Scan your project's dependencies for malware and risky code with the hosted
npm security scanner (https://security.togoder.click).

Usage
  togoder-scan [scan] [options]     Scan the lockfile in the current directory
  togoder-scan estimate [options]   Show what a scan would cost, without scanning
  togoder-scan login [key]          Save an API key (prompts, or reads stdin, if omitted)
  togoder-scan logout               Remove the saved API key
  togoder-scan account              Show access, subscription and usage for your key
  togoder-scan config path|show|set-key [key]|set-url <url>|unset-url

Options
  -l, --lockfile <path>     Lockfile or project directory (default: ./package-lock.json,
                            else npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock or bun.lock)
  -k, --api-key <key>       API key (default: $NPM_SCANNER_KEY, then the saved key)
      --url <url>           Server (default: $NPM_SCANNER_URL or https://security.togoder.click)
      --fail-on <severity>  Exit 1 on unignored findings at or above: low, medium,
                            high (default), critical, or none
      --allow-failed        Don't fail when a package could not be analyzed
      --ignore-file <path>  Ignore list (default: ${IGNORE_FILE} next to the lockfile, or in .)
      --ignore <entry>      Ignore a finding ID or package; repeatable
      --no-ignore           Don't read the ignore file
      --json                Print the JSON response instead of the report
      --sarif               Print SARIF 2.1.0 (GitHub code scanning) instead of the report
  -o, --output <file>       Write the JSON (or with --sarif, SARIF) to a file and print the report
      --min-severity <sev>  List findings at or above this severity (default: medium,
                            or --fail-on when lower); the summary counts all of them
      --show-ignored        List ignored findings too
  -v, --verbose             Show code snippets, full descriptions and recommendations
  -q, --quiet               No progress output
      --timeout <minutes>   Give up waiting after this long (default: 60)
      --no-color            Disable colors (NO_COLOR is respected too)
  -h, --help                Show this help
      --version             Show the version

Exit codes
  0  no findings at or above --fail-on, every package analyzed
  1  findings at or above --fail-on, or packages that could not be analyzed
  2  usage, lockfile, network, authentication or payment error

Ignore file (${IGNORE_FILE}), one entry per line, "#" starts a comment:
  NPS-3F9A0C1B2D4E           # a finding, in any version
  NPS-3F9A0C1B2D4E@1.2.3     # a finding, in that version only
  left-pad@1.3.0             # every finding of a package version
  left-pad                   # every finding of a package
`;

const OPTIONS = {
  lockfile: { type: "string", short: "l" },
  "api-key": { type: "string", short: "k" },
  url: { type: "string" },
  "fail-on": { type: "string" },
  "allow-failed": { type: "boolean" },
  "ignore-file": { type: "string" },
  ignore: { type: "string", multiple: true },
  "no-ignore": { type: "boolean" },
  json: { type: "boolean" },
  sarif: { type: "boolean" },
  output: { type: "string", short: "o" },
  "show-ignored": { type: "boolean" },
  "min-severity": { type: "string" },
  verbose: { type: "boolean", short: "v" },
  quiet: { type: "boolean", short: "q" },
  timeout: { type: "string" },
  "no-color": { type: "boolean" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean" },
};

class UsageError extends Error {}

export async function main(argv) {
  let flags;
  let positionals;
  try {
    ({ values: flags, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true }));
  } catch (error) {
    process.stderr.write(`togoder-scan: ${error.message}\nRun "togoder-scan --help" for usage.\n`);
    return EXIT.ERROR;
  }
  if (flags.help) {
    process.stdout.write(HELP);
    return EXIT.OK;
  }
  if (flags.version) {
    process.stdout.write(VERSION + "\n");
    return EXIT.OK;
  }

  const err = colorsFor(process.stderr, flags["no-color"]);
  const [command = "scan", ...args] = positionals;
  try {
    const config = await readConfig();
    const settings = resolveSettings(flags, config);
    const ctx = { flags, args, settings, err };
    switch (command) {
      case "scan":
        return await cmdScan(ctx, { estimateOnly: false });
      case "estimate":
        return await cmdScan(ctx, { estimateOnly: true });
      case "login":
        return await cmdSetKey(ctx, args[0]);
      case "logout":
        await updateConfig({ apiKey: undefined });
        process.stderr.write(`Removed the saved API key from ${configPath()}\n`);
        return EXIT.OK;
      case "account":
        return await cmdAccount(ctx);
      case "config":
        return await cmdConfig(ctx);
      case "help":
        process.stdout.write(HELP);
        return EXIT.OK;
      default:
        throw new UsageError(`Unknown command "${command}"`);
    }
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`togoder-scan: ${error.message}\nRun "togoder-scan --help" for usage.\n`);
      return EXIT.ERROR;
    }
    if (error instanceof ApiError || error.code === "LOCKFILE" || error.code === "IGNORE") {
      if (flags.json) {
        process.stdout.write(JSON.stringify({ status: "error", error: error.message, httpStatus: error.status ?? null }) + "\n");
      }
      process.stderr.write(`${err.red("Error:")} ${error.message}\n`);
      return EXIT.ERROR;
    }
    throw error;
  }
}

function clientFor({ settings }) {
  return createClient({ url: settings.url, apiKey: settings.apiKey, userAgent: `togoder-scan/${VERSION} node/${process.versions.node}` });
}

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

// ============================================================================
// Inputs
// ============================================================================

async function isFile(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

/** The lockfile to scan: --lockfile (a file or a directory), else the first one found in . */
async function findLockfile(option) {
  let dir = process.cwd();
  if (option) {
    const path = resolve(option);
    let info;
    try {
      info = await stat(path);
    } catch {
      throw fail("LOCKFILE", `Lockfile not found: ${option}`);
    }
    if (info.isFile()) return loadLockfile(path);
    dir = path;
  }

  for (const name of LOCKFILES) {
    if (await isFile(join(dir, name))) return loadLockfile(join(dir, name));
  }
  const where = relative(process.cwd(), dir) || "the current directory";
  if (await isFile(join(dir, "bun.lockb"))) {
    throw fail(
      "LOCKFILE",
      `Only a binary bun.lockb in ${where}, which the scanner can't read. Convert it to the text bun.lock format:\n  bun install --save-text-lockfile --frozen-lockfile --lockfile-only`
    );
  }
  if (await isFile(join(dir, "package.json"))) {
    throw fail(
      "LOCKFILE",
      `No lockfile in ${where} (looked for ${LOCKFILES.join(", ")}). Without one only direct dependencies could be scanned. Create one with:\n  npm install --package-lock-only`
    );
  }
  throw fail("LOCKFILE", `No lockfile in ${where} (looked for ${LOCKFILES.join(", ")}). Run it in your project directory or pass --lockfile <path>.`);
}

async function loadLockfile(path) {
  const info = await stat(path);
  if (info.size > MAX_UPLOAD_BYTES) {
    throw fail("LOCKFILE", `${path} is ${(info.size / 1024 / 1024).toFixed(1)} MB; the server accepts at most 10 MB`);
  }
  const content = await readFile(path);
  if (content.length === 0) throw fail("LOCKFILE", `${path} is empty`);
  const rel = relative(process.cwd(), path) || basename(path);
  return { path, content, name: basename(path), rel, uri: rel.split(sep).join("/") };
}

/** Ignore rules from the ignore file and --ignore; malformed entries are an error, as on the server */
async function loadIgnore(flags, lockfile) {
  const sources = [];
  if (!flags["no-ignore"]) {
    let path = flags["ignore-file"] ? resolve(flags["ignore-file"]) : null;
    if (path && !(await isFile(path))) throw fail("IGNORE", `Ignore file not found: ${flags["ignore-file"]}`);
    if (!path) {
      for (const candidate of [join(dirname(lockfile.path), IGNORE_FILE), resolve(IGNORE_FILE)]) {
        if (await isFile(candidate)) {
          path = candidate;
          break;
        }
      }
    }
    if (path) sources.push({ name: relative(process.cwd(), path) || IGNORE_FILE, text: await readFile(path, "utf8") });
  }
  if (flags.ignore?.length) sources.push({ name: "--ignore", text: flags.ignore.join("\n") });

  const rules = [];
  const errors = [];
  for (const source of sources) {
    const parsed = parseIgnoreText(source.text, source.name);
    rules.push(...parsed.rules);
    errors.push(...parsed.errors);
  }
  if (errors.length > 0) throw fail("IGNORE", `Invalid ignore list:\n  ${errors.slice(0, 20).join("\n  ")}`);
  return { rules, file: sources.find((s) => s.name !== "--ignore")?.name ?? null };
}

function parseTimeout(value) {
  if (value === undefined) return 60 * 60 * 1000;
  const minutes = Number(value);
  if (!Number.isFinite(minutes) || minutes <= 0) throw new UsageError(`--timeout takes a number of minutes, got "${value}"`);
  return minutes * 60 * 1000;
}

// ============================================================================
// scan / estimate
// ============================================================================

const fmt = (n) => Number(n ?? 0).toLocaleString("en-US");
const usd = (n) => `$${Number(n ?? 0).toFixed(Number(n) > 0 && Number(n) < 0.01 ? 4 : 2)}`;
const plural = (n, word) => `${fmt(n)} ${word}${n === 1 ? "" : "s"}`;

async function cmdScan(ctx, { estimateOnly }) {
  const { flags, settings } = ctx;
  const failOn = (flags["fail-on"] ?? "high").toLowerCase();
  if (!FAIL_ON.includes(failOn)) throw new UsageError(`--fail-on takes one of ${FAIL_ON.join(", ")}`);
  if (flags.json && flags.sarif) throw new UsageError("Use either --json or --sarif");
  const minSeverity = (flags["min-severity"] ?? (failOn === "low" ? "low" : "medium")).toLowerCase();
  if (!SEVERITIES.includes(minSeverity)) throw new UsageError(`--min-severity takes one of ${SEVERITIES.join(", ")}`);
  const timeoutMs = parseTimeout(flags.timeout);

  const lockfile = await findLockfile(flags.lockfile);
  const ignore = estimateOnly ? { rules: [], file: null } : await loadIgnore(flags, lockfile);
  const client = clientFor(ctx);
  const deadline = Date.now() + timeoutMs;
  const progress = createProgress(process.stderr, !flags.quiet);
  const onDownload = (p) => progress.update(`Downloading and hashing packages${p ? ` ${p.done}/${p.total}` : ""}`, "download");

  try {
    progress.update(`Uploading ${lockfile.rel} to ${settings.url}`, "upload");
    let quote = await getQuote(client, lockfile, { onProgress: onDownload, deadline });

    if (estimateOnly) {
      progress.stop();
      if (!quote) throw new ApiError(`${settings.url} does not support price quotes (no /api/quotes); run a scan instead`);
      return await printEstimate(ctx, lockfile, quote);
    }

    // Billable scans need a key (or, where the server offers it, an x402 wallet, which this CLI does not sign for)
    if (quote && !quote.free && !settings.apiKey) {
      progress.stop();
      if (flags.json) {
        process.stdout.write(JSON.stringify({ status: "error", error: "Payment required: no API key", httpStatus: 402, quote }) + "\n");
      }
      await printPaymentHelp(ctx, quote, "This scan needs payment");
      return EXIT.ERROR;
    }

    const ignoreText = formatIgnoreRules(ignore.rules);
    const onScan = (p) => progress.update(`${p?.stage || "Scanning packages"}${p ? ` ${p.done}/${p.total}` : ""}`, "scan");
    if (!quote) progress.update("Uploading lockfile; the server downloads packages before answering", "legacy");
    let response;
    try {
      response = await runScan(client, { quoteId: quote?.quoteId, lockfile, ignoreText, onProgress: onScan, deadline });
    } catch (error) {
      // A quote lives an hour and is lost on restart: price again once
      if (!(error instanceof ApiError && quote && (error.status === 410 || error.status === 409))) throw error;
      quote = await getQuote(client, lockfile, { onProgress: onDownload, deadline });
      response = await runScan(client, { quoteId: quote?.quoteId, lockfile, ignoreText, onProgress: onScan, deadline });
    }
    progress.stop();
    return await report(ctx, { response, lockfile, ignore, failOn, minSeverity });
  } catch (error) {
    progress.stop();
    if (error instanceof ApiError) return await explainScanError(ctx, error);
    throw error;
  }
}

async function report(ctx, { response, lockfile, ignore, failOn, minSeverity }) {
  const { flags, settings } = ctx;
  const allowFailed = Boolean(flags["allow-failed"]);
  const analysis = analyze(response, ignore.rules);

  const machine = flags.sarif
    ? renderSarif(analysis, { lockfileUri: lockfile.uri, lockfileContent: lockfile.content.toString("utf8"), version: VERSION, url: settings.url, allowFailed })
    : JSON.stringify(annotatedResponse(analysis), null, 2) + "\n";

  if (flags.output) {
    await writeFile(flags.output, machine);
  } else if (flags.json || flags.sarif) {
    process.stdout.write(machine);
  }

  if (flags.output || !(flags.json || flags.sarif)) {
    const c = colorsFor(process.stdout, flags["no-color"]);
    let text = renderText(analysis, {
      c,
      verbose: flags.verbose,
      showIgnored: flags["show-ignored"],
      minSeverity,
      failOn,
      allowFailed,
      lockfileName: lockfile.rel,
      ignoreFile: ignore.file || IGNORE_FILE,
      url: settings.url,
    });
    if (response.access) {
      const a = response.access;
      text += c.gray(
        `Used ${fmt(a.llmTokensUsed)} tokens; ${fmt(a.llmTokensLast30Days)} of ${fmt(a.monthlyTokenLimit)} in the last 30 days. Access until ${a.until}.`
      ) + "\n";
    }
    if (response.payment?.txHash) text += c.gray(`Paid ${usd(response.payment.amount)} (tx ${response.payment.txHash})`) + "\n";
    if (flags.output) text += c.gray(`Wrote ${flags.sarif ? "SARIF" : "JSON"} to ${flags.output}`) + "\n";
    process.stdout.write(text);
  }

  return failureReasons(analysis, { failOn, allowFailed }).length > 0 ? EXIT.FINDINGS : EXIT.OK;
}

async function fetchJson(client, path, auth = false) {
  try {
    const res = await client.request("GET", path, { auth, timeoutMs: 15_000 });
    return res.status === 200 ? res.body : null;
  } catch {
    return null;
  }
}

async function printEstimate(ctx, lockfile, quote) {
  const { flags, settings } = ctx;
  const client = clientFor(ctx);
  const account = settings.apiKey ? await fetchJson(client, "/api/account", true) : null;

  if (flags.json) {
    process.stdout.write(JSON.stringify({ ...quote, account: account ? { access: account.access, usage: account.usage, monthlyTokenLimit: account.monthlyTokenLimit } : null }, null, 2) + "\n");
    return EXIT.OK;
  }
  const c = colorsFor(process.stdout, flags["no-color"]);
  const lines = [
    `${c.bold(lockfile.rel)}: ${plural(quote.packages, "package")}, ${fmt(quote.packagesWithNewFiles)} with files never scanned before`,
  ];
  if (quote.skipped?.length) lines.push(c.yellow(`  ${quote.skipped.length} packages could not be downloaded and would be skipped`));
  if (quote.free) {
    lines.push(`  ${c.green("Free:")} every file was scanned before, so the scan needs no payment or key.`);
  } else {
    lines.push(`  New content: ${plural(quote.billableFiles, "file")}, ${fmt(quote.billableTokens)} tokens (of ${fmt(quote.totalTokens)} in total)`);
    if (quote.payPerScan === true) lines.push(`  Pay per scan (x402): ${c.bold(usd(quote.priceUsd))}`);
    if (typeof quote.balancePriceUsd === "number") lines.push(`  From a prepaid balance: ${c.bold(usd(quote.balancePriceUsd))}`);
    if (account?.access?.active) {
      const left = Math.max(0, (account.monthlyTokenLimit || 0) - (account.usage?.llmTokens || 0));
      const fits = !account.monthlyTokenLimit || quote.billableTokens <= left;
      lines.push(
        `  With your API key: ${fits ? c.green("included") : c.red("over your limit")} (~${fmt(quote.billableTokens)} of ${fmt(left)} tokens left this 30 days)`
      );
    } else if (account) {
      lines.push(`  Your API key has no active access; see "togoder-scan account".`);
    } else if (settings.apiKey) {
      lines.push(c.yellow(`  Could not check your API key's access.`));
    } else {
      lines.push(`  With an API key (monthly access) it is included; see "togoder-scan login".`);
    }
  }
  lines.push(c.gray(`  Quote ${quote.quoteId}, valid until ${quote.expiresAt}`));
  process.stdout.write(lines.join("\n") + "\n");
  return EXIT.OK;
}

async function printPaymentHelp(ctx, quote, headline) {
  const { settings, err } = ctx;
  const offer = await fetchPlans(clientFor(ctx));
  // Absent on servers that don't say: don't offer it
  const payPerScan = offer?.payPerScan === true;
  const first = payPerScan ? "1. " : "";
  const lines = [`${err.yellow(headline)}${quote ? `: ${plural(quote.billableFiles, "file")} (${fmt(quote.billableTokens)} tokens) in ${plural(quote.packagesWithNewFiles, "package")} were never scanned before.${payPerScan ? ` Price: ${usd(quote.priceUsd)}.` : ""}` : "."}`];
  lines.push("", payPerScan ? "Two ways to pay:" : "To scan them:");
  if (offer?.enabled && offer.plans.length) {
    lines.push(
      `  ${first}Monthly plan: ${planRange(offer.plans)}. Sign in at ${settings.url}/account,`,
      `     pick a plan and create an API key there, then:`,
      `       togoder-scan login <key>      (or set NPM_SCANNER_KEY)`
    );
  } else {
    lines.push(`  ${first}API key: sign in at ${settings.url}/account to create one, then "togoder-scan login <key>" or set NPM_SCANNER_KEY.`);
  }
  // Absent on servers without top-ups
  if (offer?.topup?.enabled) {
    lines.push(`  Prepaid balance: top up from $${offer.topup.minUsd} at ${settings.url}/account#topup, and scans with your API key pay from it.`);
  }
  if (payPerScan) {
    lines.push(
      `  2. Pay per scan with x402 (USDC on Base): POST the lockfile to ${settings.url}/api/paid-scan with an`,
      `     x402 client such as x402-fetch. See ${settings.url}/api-docs`
    );
  }
  lines.push(
    "",
    `Packages whose files were all scanned before are free; "togoder-scan estimate" shows ${payPerScan ? "the price" : "what needs scanning"}.`
  );
  process.stderr.write(lines.join("\n") + "\n");
}

/**
 * Plans on offer, cheapest first: GET /api/plans, or /api/access/config on a
 * server from before plans. { enabled, plans: [{ id, name, tokenLimit, price, currency }] }
 */
async function fetchPlans(client) {
  const offer = await fetchJson(client, "/api/plans", true);
  if (offer && Array.isArray(offer.plans)) return offer;
  const legacy = await fetchJson(client, "/api/access/config");
  if (!legacy) return null;
  const plans = Array.isArray(legacy.plans)
    ? legacy.plans.map((p) => ({ currency: legacy.currency, ...p }))
    : legacy.enabled
      ? [{ id: null, name: "Monthly", tokenLimit: legacy.monthlyTokenLimit, price: legacy.monthlyPrice, currency: legacy.currency }]
      : [];
  return { enabled: !!legacy.enabled, plans, currentPlan: null };
}

function money(amount, currency = "USD") {
  const n = Number(amount ?? 0).toLocaleString("en-US", { maximumFractionDigits: 2 });
  return currency === "USD" ? `$${n}` : `${n} ${currency}`;
}

/** "from $30/month" */
function fromPrice(plans) {
  const cheapest = [...plans].sort((a, b) => a.price - b.price)[0];
  return cheapest ? `from ${money(cheapest.price, cheapest.currency)}/month` : "";
}

/** "Starter $30 (100M tokens), Team $99 (350M tokens) per month" */
function planRange(plans) {
  return plans.map((p) => `${p.name} ${money(p.price, p.currency)} (${tokens(p.tokenLimit)} tokens)`).join(", ") + " per month";
}

/** "100M", "1B", "10B" */
function tokens(n) {
  n = Number(n) || 0;
  if (n >= 1e9) return `${+(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${+(n / 1e6).toFixed(1)}M`;
  return fmt(n);
}

async function explainScanError(ctx, error) {
  const { flags, settings, err } = ctx;
  const body = error.body || {};
  if (flags.json) {
    process.stdout.write(JSON.stringify({ status: "error", error: body.error || error.message, httpStatus: error.status || null, ...(body.usage ? { usage: body.usage } : {}), ...(body.topupUrl ? { balanceUsd: body.balanceUsd, priceUsd: body.priceUsd, topupUrl: body.topupUrl } : {}) }) + "\n");
  }
  switch (error.status) {
    case 401:
      process.stderr.write(
        `${err.red("Error:")} the API key from ${settings.keySource} was rejected (unknown or revoked).\nCreate a new key at ${settings.url}/account and run "togoder-scan login <key>".\n`
      );
      break;
    case 402:
      if (body.accepts) {
        const price = body.details?.estimatedCostUsd;
        await printPaymentHelp(
          ctx,
          body.details ? { billableFiles: body.details.billableFiles, billableTokens: body.details.billableTokens, packagesWithNewFiles: body.details.packagesWithNewFiles, priceUsd: price } : null,
          settings.apiKey ? "Your API key has no active access, so this scan needs payment" : "This scan needs payment"
        );
      } else if (body.topupUrl) {
        // New servers: what the scan costs from the balance and where to add to it
        const short = typeof body.balanceUsd === "number" ? `Balance ${usd(body.balanceUsd)}, this scan costs ${usd(body.priceUsd)}.` : `This scan costs ${usd(body.priceUsd)} from a prepaid balance.`;
        process.stderr.write(`${err.red("Error:")} ${body.error || "Payment required"}\n${short}\nTop up at ${settings.url}${body.topupUrl}\n`);
      } else {
        process.stderr.write(`${err.red("Error:")} ${body.error || "Payment required"}${body.accessUntil ? ` (access ended ${body.accessUntil})` : ""}\nSee "togoder-scan account" and ${settings.url}/account\n`);
      }
      break;
    case 429: {
      const u = body.usage;
      process.stderr.write(
        `${err.red("Error:")} ${body.error || "Too many requests"}` +
          (u ? `\n  Used ${fmt(u.llmTokensLast30Days)} of ${fmt(u.monthlyTokenLimit)} tokens in the last 30 days; this scan needs ~${fmt(u.estimatedScanTokens)}.` : "") +
          "\n"
      );
      break;
    }
    default:
      process.stderr.write(`${err.red("Error:")} ${error.message}\n`);
  }
  return EXIT.ERROR;
}

// ============================================================================
// login / account / config
// ============================================================================

function promptHidden(question) {
  return new Promise((resolvePrompt) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    let muted = false;
    rl._writeToOutput = (s) => {
      if (!muted) rl.output.write(s);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stderr.write("\n");
      resolvePrompt(answer);
    });
    muted = true;
  });
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function cmdSetKey(ctx, given) {
  const { settings, err } = ctx;
  let key = given || ctx.flags["api-key"];
  if (!key) {
    if (process.stdin.isTTY) {
      process.stderr.write(`Create a key at ${settings.url}/account if you don't have one.\n`);
      key = await promptHidden("API key: ");
    } else {
      key = await readStdin();
    }
  }
  key = String(key || "").trim();
  if (!key) throw new UsageError("No API key given");

  const client = createClient({ url: settings.url, apiKey: key, userAgent: `togoder-scan/${VERSION}` });
  let account = null;
  try {
    const res = await client.request("GET", "/api/account", { timeoutMs: 15_000 });
    if (res.status === 401) {
      process.stderr.write(`${err.red("Error:")} ${settings.url} rejected this key (unknown or revoked). Nothing was saved.\n`);
      return EXIT.ERROR;
    }
    if (res.status === 200) account = res.body;
  } catch (error) {
    process.stderr.write(`${err.yellow("Warning:")} could not verify the key: ${error.message}\n`);
  }

  await updateConfig({ apiKey: key });
  process.stderr.write(`Saved the API key to ${configPath()}\n`);
  if (account) printAccount(account, null, err, process.stderr, settings.url);
  return EXIT.OK;
}

const day = (iso) => (iso ? String(iso).slice(0, 10) : "?");

function printAccount(account, offer, c, stream, url) {
  const lines = [];
  const access = account.access || {};
  const active = access.active;
  const sub = account.subscription;
  const planName = (id) => offer?.plans?.find((p) => p.id === id)?.name || (id ? id[0].toUpperCase() + id.slice(1) : null);
  const plan = planName(sub?.plan ?? offer?.currentPlan ?? null);

  lines.push(`Plan:         ${active ? c.bold(plan || "monthly access") : c.yellow("none")}`);
  if (active) {
    const renews = sub && ["active", "trialing", "past_due"].includes(sub.status) && sub.scheduledChange !== "cancel";
    lines.push(`Access:       ${c.green(`active until ${day(access.until)}`)}${renews ? " (renews)" : ""}`);
  } else {
    lines.push(`Access:       ${c.yellow(access.until ? `ended ${day(access.until)}` : "none yet")}`);
  }
  if (sub) {
    let status = sub.status.replace("_", " ");
    if (sub.status === "past_due") status = c.red("past due: the last payment failed, update the card in the billing portal");
    if (sub.scheduledChange === "cancel") status += c.yellow(`, cancels ${day(access.until)}`);
    else if (sub.scheduledChange) status += c.yellow(`, ${sub.scheduledChange} scheduled`);
    lines.push(`Subscription: ${status}`);
    if (!sub.tokenLimit && sub.previousPlan && sub.previousPlan.plan !== sub.plan) {
      lines.push(`              ${planName(sub.previousPlan.plan)} limit until ${day(sub.previousPlan.until)}, then ${plan}`);
    }
  }
  const u = account.usage || {};
  // subscription.tokenLimit: the limit now and the plan's own limit from planFrom
  const tl = sub?.tokenLimit;
  let limitNote = active ? "" : c.gray(" (with a plan)");
  if (active && tl && tl.current !== tl.plan && tl.planFrom) {
    limitNote = tl.prorated
      ? ` (prorated after a mid-period upgrade; ${tokens(tl.plan)} from ${day(tl.planFrom)})`
      : ` (until ${day(tl.planFrom)}, then ${tokens(tl.plan)} on ${plan})`;
  }
  lines.push(`Token limit:  ${tokens(account.monthlyTokenLimit)} per 30 days${limitNote}`);
  lines.push(`Last 30 days: ${fmt(u.scans)} scans, ${fmt(u.packages)} packages, ${fmt(u.llmTokens)} of ${fmt(account.monthlyTokenLimit)} tokens`);
  // Absent on servers without top-ups, and when they are off
  if (offer?.topup?.enabled && typeof account.balanceUsd === "number") lines.push(`Balance:      ${usd(account.balanceUsd)} prepaid${url ? c.gray(` (top up at ${url}/account#topup)`) : ""}`);
  if (!active && (!sub || ["canceled", "paused"].includes(sub.status))) {
    const price = offer?.enabled && offer.plans?.length ? ` (plans ${fromPrice(offer.plans)})` : "";
    lines.push(c.gray(`Subscribe at ${url ? `${url}/account` : "the account page"}${price}.`));
  } else if (sub && sub.status !== "canceled" && url) {
    lines.push(c.gray(`Manage the plan and billing at ${url}/account`));
  }
  stream.write(lines.join("\n") + "\n");
}

async function cmdAccount(ctx) {
  const { flags, settings } = ctx;
  if (!settings.apiKey) {
    process.stderr.write(`No API key. Sign in at ${settings.url}/account to create one, then run "togoder-scan login <key>" or set NPM_SCANNER_KEY.\n`);
    return EXIT.ERROR;
  }
  const client = clientFor(ctx);
  const res = await client.request("GET", "/api/account", { timeoutMs: 15_000 });
  if (res.status === 401) {
    throw new ApiError(`The API key from ${settings.keySource} was rejected (unknown or revoked)`, { status: 401 });
  }
  if (res.status !== 200) throw errorFrom(res, "Could not load the account");
  if (flags.json) {
    process.stdout.write(JSON.stringify(res.body, null, 2) + "\n");
    return EXIT.OK;
  }
  const offer = await fetchPlans(client);
  printAccount(res.body, offer, colorsFor(process.stdout, flags["no-color"]), process.stdout, settings.url);
  process.stdout.write(`Key from:     ${settings.keySource}\nServer:       ${settings.url}\n`);
  return EXIT.OK;
}

async function cmdConfig(ctx) {
  const [sub, value] = ctx.args;
  switch (sub) {
    case "path":
      process.stdout.write(configPath() + "\n");
      return EXIT.OK;
    case "show":
    case undefined: {
      const config = await readConfig();
      const masked = config.apiKey ? `${config.apiKey.slice(0, 8)}…` : null;
      process.stdout.write(JSON.stringify({ path: configPath(), ...config, apiKey: masked }, null, 2) + "\n");
      return EXIT.OK;
    }
    case "set-key":
      return await cmdSetKey(ctx, value);
    case "unset-key":
      await updateConfig({ apiKey: undefined });
      return EXIT.OK;
    case "set-url":
      if (!value || !/^https?:\/\//.test(value)) throw new UsageError("config set-url takes an http(s) URL");
      await updateConfig({ url: value.replace(/\/+$/, "") });
      return EXIT.OK;
    case "unset-url":
      await updateConfig({ url: undefined });
      return EXIT.OK;
    default:
      throw new UsageError(`Unknown config command "${sub}"`);
  }
}
