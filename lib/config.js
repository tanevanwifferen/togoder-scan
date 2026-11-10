import { mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DEFAULT_URL = "https://security.togoder.click";

/** ~/.config/npm-scanner/config.json, or under $XDG_CONFIG_HOME / %APPDATA% */
export function configPath() {
  if (process.env.NPM_SCANNER_CONFIG) return process.env.NPM_SCANNER_CONFIG;
  const base =
    process.env.XDG_CONFIG_HOME ||
    (process.platform === "win32" && process.env.APPDATA) ||
    join(homedir(), ".config");
  return join(base, "npm-scanner", "config.json");
}

export async function readConfig() {
  try {
    const parsed = JSON.parse(await readFile(configPath(), "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw new Error(`Could not read ${configPath()}: ${error.message}`);
  }
}

/** Merge `changes` into the config file; undefined values remove a key */
export async function updateConfig(changes) {
  const config = { ...(await readConfig()), ...changes };
  for (const key of Object.keys(config)) {
    if (config[key] === undefined) delete config[key];
  }
  const path = configPath();
  if (Object.keys(config).length === 0) {
    await rm(path, { force: true });
    return config;
  }
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  // The file holds an API key: readable by its owner only
  await writeFile(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  return config;
}

/** Where the API key and server URL come from: flags, then env, then config */
export function resolveSettings(flags, config) {
  const fromEnv = process.env.NPM_SCANNER_KEY?.trim();
  const apiKey = flags["api-key"]?.trim() || fromEnv || config.apiKey || "";
  const keySource = flags["api-key"]
    ? "--api-key"
    : fromEnv
      ? "NPM_SCANNER_KEY"
      : config.apiKey
        ? configPath()
        : null;
  const url = (flags.url || process.env.NPM_SCANNER_URL || config.url || DEFAULT_URL).replace(/\/+$/, "");
  return { apiKey, keySource, url };
}
