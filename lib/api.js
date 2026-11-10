import { basename } from "node:path";

/** An HTTP or network failure; `status` is 0 when the server was not reached */
export class ApiError extends Error {
  constructor(message, { status = 0, body = null } = {}) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

const REQUEST_TIMEOUT_MS = 120_000;
// A proxy hiccup or restart while polling should not lose a paid scan
const TRANSIENT = new Set([0, 502, 503, 504]);
const POLL_RETRIES = 6;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function createClient({ url, apiKey, userAgent }) {
  async function request(method, path, { form, json, auth = true, timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
    const headers = { Accept: "application/json", "User-Agent": userAgent };
    if (auth && apiKey) headers.Authorization = `Bearer ${apiKey}`;
    let body;
    if (form) body = form;
    else if (json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(json);
    }

    let res;
    try {
      res = await fetch(url + path, { method, headers, body, signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      const reason = error?.name === "TimeoutError" ? "timed out" : error?.cause?.message || error?.message || String(error);
      throw new ApiError(`Could not reach ${url} (${reason})`);
    }
    const text = await res.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    return { status: res.status, body: parsed, text };
  }

  /** request(), retried with backoff on network errors and gateway errors */
  async function requestRetrying(method, path, options) {
    for (let attempt = 0; ; attempt++) {
      try {
        const res = await request(method, path, options);
        if (!TRANSIENT.has(res.status) || attempt >= POLL_RETRIES) return res;
      } catch (error) {
        if (!(error instanceof ApiError) || attempt >= POLL_RETRIES) throw error;
      }
      await sleep(Math.min(2000 * 2 ** attempt, 30_000));
    }
  }

  return { url, apiKey, request, requestRetrying };
}

export function errorFrom(res, fallback) {
  const detail = res.body?.error || res.body?.message || (res.text && !res.body ? res.text.slice(0, 200).trim() : "");
  const details = Array.isArray(res.body?.details) ? `\n  ${res.body.details.join("\n  ")}` : "";
  return new ApiError(`${fallback} (HTTP ${res.status})${detail ? `: ${detail}` : ""}${details}`, {
    status: res.status,
    body: res.body,
  });
}

function lockfileForm(lockfile) {
  const form = new FormData();
  form.append("file", new Blob([lockfile.content]), basename(lockfile.path));
  return form;
}

/** Poll a job URL until it stops answering "running" */
async function pollJob(client, path, { onProgress, deadline, what }) {
  let delay = 1000;
  for (;;) {
    if (Date.now() > deadline) {
      throw new ApiError(`Gave up waiting for the ${what} (--timeout). It may still finish on the server: ${client.url}${path}`);
    }
    await sleep(delay);
    delay = Math.min(delay * 1.5, 5000);
    const res = await client.requestRetrying("GET", path, { auth: false });
    if (res.status === 404) throw errorFrom(res, `The ${what} expired or the server restarted; run the command again`);
    if (res.status !== 200) throw errorFrom(res, `The ${what} failed`);
    if (res.body?.status !== "running") return res.body;
    onProgress?.(res.body.progress);
  }
}

/**
 * Price a lockfile without waiting on one long request: POST /api/quotes
 * answers right away and the download runs as a job. Returns null when the
 * server has no /api/quotes.
 */
export async function getQuote(client, lockfile, { onProgress, deadline }) {
  const res = await client.request("POST", "/api/quotes", { form: lockfileForm(lockfile), auth: false });
  if (res.status === 404) return null;
  if (res.status !== 202 || !res.body?.quoteId) throw errorFrom(res, "Could not price the lockfile");
  onProgress?.();
  const quote = await pollJob(client, `/api/quotes/${encodeURIComponent(res.body.quoteId)}`, {
    onProgress,
    deadline,
    what: "price quote",
  });
  if (quote?.status !== "ready") throw new ApiError(`Could not price the lockfile: ${quote?.error || "unexpected reply"}`);
  return quote;
}

/**
 * Start a scan of a quote (or, for servers without quotes, of the lockfile
 * itself) as an async job and wait for its result. Returns the raw response
 * for 200/202, or throws ApiError with the status (401, 402, 429, ...).
 */
export async function runScan(client, { quoteId, lockfile, ignoreText, onProgress, deadline }) {
  const form = quoteId ? new FormData() : lockfileForm(lockfile);
  if (quoteId) form.append("quoteId", quoteId);
  if (ignoreText) form.append("ignore", ignoreText);

  // Without a quote the server downloads before answering: allow for that
  const timeoutMs = quoteId ? REQUEST_TIMEOUT_MS : Math.max(deadline - Date.now(), REQUEST_TIMEOUT_MS);
  const res = await client.request("POST", "/api/paid-scan?async=1", { form, timeoutMs });
  if (res.status === 200) return res.body;
  if (res.status !== 202 || !res.body?.jobId) throw errorFrom(res, "Scan request failed");
  onProgress?.();

  const result = await pollJob(client, `/api/scan-jobs/${encodeURIComponent(res.body.jobId)}`, {
    onProgress,
    deadline,
    what: "scan",
  });
  if (!result || result.status === "error") throw new ApiError(`Scan failed: ${result?.error || "unexpected reply"}`);
  return result;
}
