#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const path = require("node:path");

function releaseVersion(tag) {
  const version = tag.replace(/^v/, "");
  // SemVer grammar, including leading-zero rules for numeric identifiers.
  const numeric = "(?:0|[1-9][0-9]*)";
  const pre = `(?:${numeric}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)`;
  const pattern = new RegExp(`^${numeric}\\.${numeric}\\.${numeric}(?:-${pre}(?:\\.${pre})*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`);
  if (!pattern.test(version)) throw new Error(`Invalid release SemVer: ${tag}`);
  return version;
}

function manifest({ tag, repo, tar, pubDate = new Date().toISOString() }) {
  const version = releaseVersion(tag);
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error("Invalid repository");
  if (!tar.endsWith(".app.tar.gz") || !fs.statSync(tar).isFile()) throw new Error("Missing Mac updater archive");
  const signature = fs.readFileSync(`${tar}.sig`, "utf8").trim();
  if (!signature) throw new Error("Empty updater signature");
  return {
    version,
    notes: JSON.stringify({
      tr: "Mac güncellemesi. Yeniden açılışta core için yönetici onayı istenebilir.",
      en: "Mac update. Updating the core may require administrator approval after restart.",
    }),
    pub_date: pubDate,
    platforms: { "darwin-aarch64": {
      signature,
      url: `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(path.basename(tar))}`,
    } },
  };
}

if (require.main === module) {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "config") {
    const [tag, output] = args;
    fs.writeFileSync(output, JSON.stringify({ version: releaseVersion(tag), bundle: { createUpdaterArtifacts: false } }));
  } else if (mode === "manifest") {
    const [tag, repo, tar, output] = args;
    fs.writeFileSync(output, JSON.stringify(manifest({ tag, repo, tar }), null, 2) + "\n");
  } else {
    throw new Error("usage: mac-release.cjs config <tag> <output> | manifest <tag> <repo> <tar> <output>");
  }
}
module.exports = { releaseVersion, manifest };
