#!/usr/bin/env node
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const root = __dirname;
let cmd;
let args;

if (process.platform === "win32") {
  cmd = "powershell";
  args = [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    path.join(root, "stage-bundle.ps1"),
  ];
} else if (process.platform === "darwin") {
  cmd = "bash";
  args = [path.join(root, "stage-bundle-darwin.sh")];
} else {
  console.error(`stage-bundle: unsupported platform ${process.platform}`);
  process.exit(1);
}

const r = spawnSync(cmd, args, { stdio: "inherit" });
if (r.error) {
  console.error(r.error);
  process.exit(1);
}
process.exit(r.status == null ? 1 : r.status);
