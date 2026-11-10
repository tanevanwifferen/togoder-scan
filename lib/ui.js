/** ANSI colors for a stream, off for NO_COLOR, non-TTY output and TERM=dumb */
export function colorsFor(stream, forceOff = false) {
  const force = process.env.FORCE_COLOR;
  const enabled =
    !forceOff &&
    !("NO_COLOR" in process.env && process.env.NO_COLOR !== "") &&
    (force !== undefined && force !== "0" && force !== "false"
      ? true
      : Boolean(stream.isTTY) && process.env.TERM !== "dumb");
  const wrap = (open, close) => (s) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));
  return {
    enabled,
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    blue: wrap(34, 39),
    magenta: wrap(35, 39),
    cyan: wrap(36, 39),
    gray: wrap(90, 39),
    inverse: wrap(7, 27),
  };
}

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
// Without a TTY (CI logs) a line per stage, repeated at most this often
const PLAIN_INTERVAL_MS = 30_000;

/**
 * Progress on stderr, so stdout stays clean for --json and --sarif. A spinner
 * on a terminal; occasional plain lines in CI logs.
 */
export function createProgress(stream, enabled) {
  const tty = Boolean(stream.isTTY);
  const started = Date.now();
  let text = "";
  let stage = "";
  let frame = 0;
  let timer = null;
  let lastPlain = 0;

  const elapsed = () => {
    const s = Math.round((Date.now() - started) / 1000);
    return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s`;
  };
  const clear = () => {
    if (tty) stream.write("\r\x1b[2K");
  };
  const render = () => {
    const columns = stream.columns || 80;
    const line = `${FRAMES[frame++ % FRAMES.length]} ${text} (${elapsed()})`;
    stream.write(`\r\x1b[2K${line.slice(0, columns - 1)}`);
  };

  return {
    /** Show `message`; `key` names the stage, so CI logs get a line when it changes */
    update(message, key = message) {
      if (!enabled) return;
      text = message;
      if (tty) {
        if (!timer) {
          timer = setInterval(render, 100);
          timer.unref?.();
        }
        render();
      } else if (key !== stage || Date.now() - lastPlain >= PLAIN_INTERVAL_MS) {
        stream.write(`${message} (${elapsed()})\n`);
        lastPlain = Date.now();
      }
      stage = key;
    },
    /** Print a line without garbling the spinner */
    log(message) {
      if (!enabled) return;
      clear();
      stream.write(message + "\n");
      if (timer) render();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
      if (enabled) clear();
    },
  };
}
