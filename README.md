# togoder-scan

[![npm](https://img.shields.io/npm/v/togoder-scan)](https://www.npmjs.com/package/togoder-scan)
[![test](https://github.com/tanevanwifferen/togoder-scan/actions/workflows/test.yml/badge.svg)](https://github.com/tanevanwifferen/togoder-scan/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Scan your lockfile for **malicious dependencies**: malware, install-time payloads (`postinstall`, `setup.py`, `build.rs`), credential and token theft, crypto-wallet drainers, backdoors and obfuscated code. The scanner at [security.togoder.click](https://security.togoder.click) downloads every package in your lockfile and has an AI model read the actual source code of every file, so it catches malicious packages before an advisory exists.

```bash
npx togoder-scan
```

Works with npm, pnpm, Yarn and Bun lockfiles, and with PyPI (`poetry.lock`, ...), crates.io (`Cargo.lock`), Go modules (`go.sum`), RubyGems (`Gemfile.lock`) and Packagist (`composer.lock`). Prints a report, JSON or SARIF for GitHub code scanning. No dependencies; needs Node.js 20 or newer.

## Only your lockfile is uploaded, never your code

This CLI is a small client for the hosted scanner. It sends:

- **your lockfile**: the list of dependencies, their versions and the URLs they resolve to;
- **your ignore list**, if you have one (`.npm-scanner-ignore` and `--ignore`);
- **your API key**, if you use one.

Your own source code, other files in your repository and environment variables are **not** sent. The server downloads the dependencies itself from the public registries (npm, PyPI, crates.io, ...) and scans those. A lockfile does reveal which packages you use, including the names of private packages and the hosts of private registries; the server cannot download private packages, so those are not scanned. All scanning happens on the server; this repository contains only the client, so you can read exactly what it sends ([`lib/api.js`](lib/api.js)).

## Why not `npm audit`?

`npm audit`, Dependabot and OSV-Scanner match your dependencies against a database of **known** vulnerabilities. A freshly published malicious version (a hijacked maintainer account, a typosquat, a worm like Shai-Hulud) is not in any database until someone finds it and files an advisory, often days later. togoder-scan reads the code of each package itself and reports what it does: network calls from install scripts, reading `~/.npmrc`, `~/.ssh` or cloud credentials, downloading and running binaries, rewriting wallet addresses, decoding and executing hidden payloads.

Use both: `npm audit` for known CVEs, togoder-scan for code that is malicious.

## What it costs

Files are cached by content hash: **you only pay for file contents nobody has scanned before**. If every file in your lockfile was scanned already, the scan is free and needs no key or account. Popular packages are usually cached already.

Otherwise you need an **API key**: sign in with GitHub or Google on the [account page](https://security.togoder.click/account), top up a prepaid balance or pick a monthly plan, and create a key there. See [pricing](https://security.togoder.click/pricing). To see what needs scanning, and the price, before you pay:

```bash
npx togoder-scan estimate
```

## Usage

```bash
npx togoder-scan login            # save an API key (prompts; or: echo "$KEY" | npx togoder-scan login)
npx togoder-scan                  # scan ./package-lock.json (or the lockfile found here)
npx togoder-scan -l apps/web      # scan the lockfile in another directory
npx togoder-scan --json > scan.json
npx togoder-scan --sarif -o results.sarif
npx togoder-scan account          # access, balance and usage
```

The lockfile is looked for in this order: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` (the binary `bun.lockb` must first be converted with `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`). `--lockfile` also takes the lockfiles of the other ecosystems (`poetry.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`, ...).

| Option | |
|---|---|
| `-l, --lockfile <path>` | Lockfile, or a directory to look in |
| `-k, --api-key <key>` | API key. Default: `$NPM_SCANNER_KEY`, then the key saved by `login` |
| `--url <url>` | Server. Default: `$NPM_SCANNER_URL` or `https://security.togoder.click` |
| `--fail-on <severity>` | Exit 1 on unignored findings at or above `low`, `medium`, `high` (default), `critical`, or `none` |
| `--allow-failed` | Don't fail when a package could not be analyzed |
| `--ignore-file <path>` | Ignore list. Default: `.npm-scanner-ignore` next to the lockfile, or in the current directory |
| `--ignore <entry>` | Ignore a finding ID or package; repeatable |
| `--no-ignore` | Don't read the ignore file |
| `--json` | Print the JSON response instead of the report |
| `--sarif` | Print SARIF 2.1.0 instead of the report |
| `-o, --output <file>` | Write the JSON (or SARIF) to a file and still print the report |
| `--min-severity <sev>` | List findings at or above this severity. Default: `medium` (or `--fail-on` when lower) |
| `--show-ignored` | List ignored findings too |
| `-v, --verbose` | Code snippets, full descriptions and recommendations |
| `-q, --quiet` | No progress output |
| `--timeout <minutes>` | Stop waiting after this long. Default: 60 |
| `--no-color` | No colors. `NO_COLOR` and non-terminal output turn them off too |

Progress goes to stderr, so `--json` and `--sarif` output on stdout stays clean.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No unignored findings at or above `--fail-on`, and every package was analyzed |
| `1` | Findings at or above `--fail-on`, or packages that could not be analyzed (unless `--allow-failed`) |
| `2` | Usage, lockfile, network, authentication or payment error |

A package the scanner could not analyze (download error, model timeout) is reported as **failed**, never as safe, and fails the build unless you pass `--allow-failed`.

### Ignoring findings

Every finding has a stable ID like `NPS-3F9A0C1B2D4E`, printed next to it. After reviewing a finding, add it to `.npm-scanner-ignore` in your repository:

```
# One entry per line; text after "#" is kept as the reason
NPS-3F9A0C1B2D4E           # postinstall fetch, reviewed by the security team
NPS-0811DA3A5FA0@2.1.0     # only in this version
left-pad@1.3.0             # every finding of this package version
left-pad                   # every finding of this package
```

Ignored findings no longer fail the build and are counted separately in the summary. The list is sent to the server and also applied locally. A malformed entry is an error (exit 2), so a typo never silently ignores nothing.

IDs are derived from the package name and the file's content, so they survive rescans and version bumps that leave the file unchanged, and change when the code does.

### API key storage

`login` checks the key against the server and saves it to `~/.config/npm-scanner/config.json` (`$XDG_CONFIG_HOME`, or `%APPDATA%` on Windows), readable only by you. `logout` removes it. `config show`, `config path`, `config set-url <url>` and `config unset-url` manage the rest. In CI, use the `NPM_SCANNER_KEY` environment variable instead.

## GitHub Actions

```yaml
name: Dependency scan
on:
  pull_request:
    paths: [package-lock.json, .npm-scanner-ignore]
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # for the SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Scan dependencies
        env:
          NPM_SCANNER_KEY: ${{ secrets.NPM_SCANNER_KEY }}
        run: npx --yes togoder-scan --fail-on high --output results.sarif --sarif
      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: togoder-scan
```

The step prints the report to the log, writes SARIF for the Security tab, and fails the job on unignored high or critical findings or packages that could not be analyzed. Findings point at the dependency's line in the lockfile. Large lockfiles with many never-scanned files can take several minutes.

Without code scanning, drop the upload step and `--output`/`--sarif`.

## Links

- [Public reports](https://security.togoder.click/npm) for scanned packages, and [recent malicious packages](https://security.togoder.click/malicious-packages)
- [How the scanner works](https://security.togoder.click/methodology)
- [API documentation](https://security.togoder.click/api-docs), to call the scanner without this CLI

## License

[MIT](LICENSE)
