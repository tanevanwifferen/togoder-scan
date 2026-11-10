#!/usr/bin/env node
import { main } from "../lib/cli.js";

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    process.stderr.write(`togoder-scan: ${error?.stack || error}\n`);
    process.exitCode = 2;
  }
);
