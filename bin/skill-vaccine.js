#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const packageRoot = path.resolve(__dirname, "..");
const sourceRoot = path.join(packageRoot, "src");
const existingPythonPath = process.env.PYTHONPATH;
const pythonPath = existingPythonPath ? `${sourceRoot}${path.delimiter}${existingPythonPath}` : sourceRoot;

const candidates = process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"];
let lastResult = null;

for (const candidate of candidates) {
  const args = candidate === "py" ? ["-3", "-m", "skillshield"] : ["-m", "skillshield"];
  const result = spawnSync(candidate, args.concat(process.argv.slice(2)), {
    env: { ...process.env, PYTHONPATH: pythonPath },
    stdio: "inherit"
  });
  if (result.error && result.error.code === "ENOENT") {
    lastResult = result;
    continue;
  }
  if (result.error) {
    console.error(`Skill Vaccine: failed to launch ${candidate}: ${result.error.message}`);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

console.error("Skill Vaccine: Python 3.11+ is required but was not found on PATH.");
if (lastResult && lastResult.error && lastResult.error.message) {
  console.error(lastResult.error.message);
}
process.exit(1);

