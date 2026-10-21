#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { releaseVersion } = require("./mac-release.cjs");
const ROOT = path.resolve(__dirname, "..");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const readJSON = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const json = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");

function compareVersions(a, b) {
  const parts = (v) => {
    const [base, ...pre] = releaseVersion(v).split("+")[0].split("-");
    return { base: base.split(".").map(Number), pre: pre.length ? pre.join("-").split(".") : null };
  };
  const x = parts(a), y = parts(b);
  for (let i = 0; i < 3; i++) if (x.base[i] !== y.base[i]) return Math.sign(x.base[i] - y.base[i]);
  if (!x.pre || !y.pre) return x.pre === y.pre ? 0 : x.pre ? -1 : 1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i], q = y.pre[i];
    if (p === undefined || q === undefined) return p === q ? 0 : p === undefined ? -1 : 1;
    if (p === q) continue;
    const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
    if (pn && qn) return p.length === q.length ? (p < q ? -1 : 1) : Math.sign(p.length - q.length);
    if (pn !== qn) return pn ? -1 : 1;
    return p < q ? -1 : 1;
  }
  return 0;
}

function checkVersions(tag) {
  const version = releaseVersion(tag);
  for (const file of ["offveil-ui/package.json", "offveil-ui/src-tauri/tauri.conf.json", "offveil-ui/src/whats-new.json", "offveil-ui/src/whats-new.macos.json"]) {
    if (readJSON(path.join(ROOT, file)).version !== version) throw new Error(`Version mismatch: ${file}`);
  }
  const npmLock = readJSON(path.join(ROOT, "offveil-ui/package-lock.json"));
  if (npmLock.version !== version || npmLock.packages[""].version !== version) throw new Error("npm lock version mismatch");
  const cargo = fs.readFileSync(path.join(ROOT, "offveil-ui/src-tauri/Cargo.toml"), "utf8");
  const cargoLock = fs.readFileSync(path.join(ROOT, "offveil-ui/src-tauri/Cargo.lock"), "utf8");
  const core = fs.readFileSync(path.join(ROOT, "offveil-core/internal/version/version.go"), "utf8");
  if (!cargo.includes(`version = "${version}"`) || (!cargoLock.includes(`name = "offveil-ui"\nversion = "${version}"`) &&
      !cargoLock.includes(`name = "offveil-ui"\r\nversion = "${version}"`)) || !core.includes(`var Version = "${version}"`)) {
    throw new Error("Rust/core version mismatch");
  }
  return version;
}

// Match the Minisign format used by Tauri: verify the payload and trusted comment.
function verifyUpdaterSignature(bytes, encodedSignature, encodedPublicKey) {
  const keyLines = Buffer.from(encodedPublicKey.trim(), "base64").toString("utf8").trim().split(/\r?\n/);
  const sigLines = Buffer.from(encodedSignature.trim(), "base64").toString("utf8").trim().split(/\r?\n/);
  const key = Buffer.from(keyLines[1] || "", "base64");
  const sig = Buffer.from(sigLines[1] || "", "base64");
  const global = Buffer.from(sigLines[3] || "", "base64");
  if (key.length !== 42 || sig.length !== 74 || global.length !== 64 ||
      !sigLines[2]?.startsWith("trusted comment: ") || !key.subarray(2, 10).equals(sig.subarray(2, 10))) {
    throw new Error("Invalid updater signature/key format");
  }
  const algorithm = sig.subarray(0, 2).toString("ascii");
  if (algorithm !== "ED" && algorithm !== "Ed") throw new Error("Unsupported updater signature algorithm");
  const publicKey = crypto.createPublicKey({ key: Buffer.concat([SPKI, key.subarray(10)]), format: "der", type: "spki" });
  const message = algorithm === "ED" ? crypto.createHash("blake2b512").update(bytes).digest() : bytes;
  const trusted = Buffer.concat([sig.subarray(10), Buffer.from(sigLines[2].slice("trusted comment: ".length))]);
  if (!crypto.verify(null, message, publicKey, sig.subarray(10)) || !crypto.verify(null, trusted, publicKey, global)) {
    throw new Error("Updater signature verification failed");
  }
}

function assetNames(version) {
  const prefix = `offveil_${version}`;
  return [`${prefix}_x64-setup.exe`, `${prefix}_x64-setup.exe.sig`, `${prefix}_aarch64.dmg`,
    `${prefix}_aarch64.app.tar.gz`, `${prefix}_aarch64.app.tar.gz.sig`,
    "latest.json", "latest-mac.json", "active.json", "active.json.sig"];
}

function verifyPayloads(dir, tag, repo, pubkey) {
  const version = releaseVersion(tag);
  const base = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/`;
  const windows = readJSON(path.join(dir, "latest.json"));
  const mac = readJSON(path.join(dir, "latest-mac.json"));
  for (const doc of [windows, mac]) {
    if (doc.version !== version || !Number.isFinite(Date.parse(doc.pub_date))) throw new Error("Invalid update version/date");
    const notes = JSON.parse(doc.notes);
    if (!notes.tr?.trim() || !notes.en?.trim()) throw new Error("Missing localized update notes");
  }
  for (const [doc, target, file] of [[windows, "windows-x86_64", `offveil_${version}_x64-setup.exe`],
    [mac, "darwin-aarch64", `offveil_${version}_aarch64.app.tar.gz`]]) {
    const platform = doc.platforms?.[target];
    const signature = fs.readFileSync(path.join(dir, `${file}.sig`), "utf8").trim();
    if (platform?.url !== base + encodeURIComponent(file) || platform.signature !== signature) throw new Error(`Invalid ${target} update entry`);
    verifyUpdaterSignature(fs.readFileSync(path.join(dir, file)), signature, pubkey);
  }
  for (const doc of [windows, mac]) for (const platform of Object.values(doc.platforms)) {
    if (!platform.signature?.trim() || !platform.url?.startsWith(base)) throw new Error("Incomplete/foreign update platform");
  }
  const channel = readJSON(path.join(ROOT, "ruleset/channel.json"));
  const rulesetKey = crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(channel.public_key_hex, "hex")]), format: "der", type: "spki" });
  if (!crypto.verify(null, fs.readFileSync(path.join(dir, "active.json")), rulesetKey,
    Buffer.from(fs.readFileSync(path.join(dir, "active.json.sig"), "utf8").trim(), "base64"))) {
    throw new Error("Ruleset signature verification failed");
  }
  return { windows, mac };
}

function prepare(dir, tag, repo, bodyFile) {
  const version = checkVersions(tag);
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error("Invalid GitHub repository");
  for (const name of assetNames(version)) if (!fs.statSync(path.join(dir, name)).isFile()) throw new Error(`Missing ${name}`);
  const pubkey = readJSON(path.join(ROOT, "offveil-ui/src-tauri/tauri.conf.json")).plugins.updater.pubkey;
  const { windows, mac } = verifyPayloads(dir, tag, repo, pubkey);
  windows.platforms["darwin-aarch64"] = mac.platforms["darwin-aarch64"];
  windows.platforms["aarch64-apple-darwin"] = mac.platforms["darwin-aarch64"];
  json(path.join(dir, "latest.json"), windows);
  const sums = assetNames(version).map((name) => `${sha256(fs.readFileSync(path.join(dir, name)))}  ${name}`).join("\n") + "\n";
  fs.writeFileSync(path.join(dir, "SHA256SUMS.txt"), sums);
  const body = fs.readFileSync(path.join(ROOT, ".github/release-body.md"), "utf8")
    .replaceAll("{{VERSION}}", version).replaceAll("{{TAG}}", tag)
    .replaceAll("{{DOWNLOAD_BASE}}", `https://github.com/${repo}/releases/download/${tag}`);
  if (/\{\{\w+\}\}/.test(body)) throw new Error("Unresolved release body placeholder");
  fs.writeFileSync(bodyFile, body);
  return [...assetNames(version), "SHA256SUMS.txt"];
}

// A prerelease cannot be GitHub Latest. Keep old Windows clients' endpoint
// useful by changing only its update pointer and the matching checksum entry.
function bridge(legacyDir, releaseDir) {
  const old = readJSON(path.join(legacyDir, "latest.json"));
  const next = readJSON(path.join(releaseDir, "latest.json"));
  if (compareVersions(next.version, old.version) <= 0) throw new Error("Legacy update bridge would not advance the version");
  fs.copyFileSync(path.join(releaseDir, "latest.json"), path.join(legacyDir, "latest.json"));
  const checksumFile = path.join(legacyDir, "SHA256SUMS.txt");
  const lines = fs.readFileSync(checksumFile, "utf8").trim().split(/\r?\n/).filter((line) => !/\s\*?latest\.json$/.test(line));
  lines.push(`${sha256(fs.readFileSync(path.join(legacyDir, "latest.json")))}  latest.json`);
  fs.writeFileSync(checksumFile, lines.join("\n") + "\n");
}

async function fetchBytes(url) {
  const headers = new URL(url).hostname === "api.github.com" && process.env.GH_TOKEN
    ? { Authorization: `Bearer ${process.env.GH_TOKEN}`, Accept: "application/vnd.github+json" } : {};
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(120_000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${url}`);
  return Buffer.from(await response.arrayBuffer());
}

async function verifyPublished(tag, repo, dir) {
  const version = releaseVersion(tag);
  fs.mkdirSync(dir, { recursive: true });
  const release = JSON.parse(await fetchBytes(`https://api.github.com/repos/${repo}/releases/tags/${tag}`));
  if (release.draft || release.prerelease !== version.includes("-")) throw new Error("Incorrect release publication state");
  for (const name of [...assetNames(version), "SHA256SUMS.txt"]) {
    const asset = release.assets.find((a) => a.name === name && a.state === "uploaded");
    if (!asset) throw new Error(`Published release is missing ${name}`);
    const bytes = await fetchBytes(asset.browser_download_url);
    fs.writeFileSync(path.join(dir, name), bytes);
    if (asset.digest && asset.digest !== `sha256:${sha256(bytes)}`) throw new Error(`GitHub digest mismatch: ${name}`);
  }
  for (const line of fs.readFileSync(path.join(dir, "SHA256SUMS.txt"), "utf8").trim().split(/\r?\n/)) {
    const [, digest, name] = /^([a-f0-9]{64})\s+(.+)$/.exec(line) || [];
    if (!assetNames(version).includes(name) || sha256(fs.readFileSync(path.join(dir, name))) !== digest) throw new Error(`Checksum mismatch: ${name}`);
  }
  const currentKey = readJSON(path.join(ROOT, "offveil-ui/src-tauri/tauri.conf.json")).plugins.updater.pubkey;
  const { windows } = verifyPayloads(dir, tag, repo, currentKey);
  const windowsLive = JSON.parse(await fetchBytes(`https://github.com/${repo}/releases/latest/download/latest.json`));
  const releases = JSON.parse(await fetchBytes(`https://api.github.com/repos/${repo}/releases?per_page=100`)).filter((r) => {
    try { releaseVersion(r.tag_name); return true; } catch { return false; }
  });
  const sharedPriorVersions = ["v1.0.3", "v1.0.4-beta.1", "v1.0.4-beta.2", "v1.0.4-beta.3"];
  for (const prior of ["v1.0.0-b4", "v1.0.0-b5", "v1.0.0-mac.3", "v1.0.0-mac.4", "v1.0.0", ...sharedPriorVersions]) {
    const old = JSON.parse(execFileSync("git", ["show", `${prior}:offveil-ui/src-tauri/tauri.conf.json`], { cwd: ROOT, encoding: "utf8" }));
    if (old.plugins.updater.pubkey !== currentKey || compareVersions(version, prior) <= 0) throw new Error(`Incompatible prior client ${prior}`);
    if (!prior.includes("-mac") && (windowsLive.version !== version ||
      JSON.stringify(windowsLive.platforms["windows-x86_64"]) !== JSON.stringify(windows.platforms["windows-x86_64"]) ||
      old.plugins.updater.endpoints[0] !== `https://github.com/${repo}/releases/latest/download/latest.json`)) {
      throw new Error(`${prior} Windows update endpoint does not offer ${tag}`);
    }
    if (prior.includes("-mac") || sharedPriorVersions.includes(prior)) {
      const candidate = releases.filter((r) => !r.draft && compareVersions(r.tag_name, prior) > 0 &&
        ["latest-mac.json", `offveil_${releaseVersion(r.tag_name)}_aarch64.app.tar.gz`, `offveil_${releaseVersion(r.tag_name)}_aarch64.app.tar.gz.sig`]
          .every((name) => r.assets.some((a) => a.name === name && a.state === "uploaded"))
      ).sort((a, b) => compareVersions(b.tag_name, a.tag_name))[0];
      if (candidate?.tag_name !== tag) throw new Error(`${prior} Mac update discovery does not offer ${tag}`);
    }
    console.log(`${prior} -> ${tag}: discovery, version and signing key verified`);
  }
  console.log("Published Windows/Mac payload signatures, ruleset signature and all checksums verified.");
}

if (require.main === module) {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "check") console.log(checkVersions(args[0]));
  else if (mode === "verify-updater") {
    const pubkey = readJSON(path.join(ROOT, "offveil-ui/src-tauri/tauri.conf.json")).plugins.updater.pubkey;
    verifyUpdaterSignature(fs.readFileSync(args[0]), fs.readFileSync(args[1], "utf8"), pubkey);
    console.log(`Verified updater signature: ${path.basename(args[0])}`);
  }
  else if (mode === "prepare") console.log(prepare(args[2], args[0], args[1], args[3]).join("\n"));
  else if (mode === "bridge") bridge(args[0], args[1]);
  else if (mode === "verify-published") verifyPublished(args[0], args[1], args[2]).catch((err) => { console.error(err.message); process.exitCode = 1; });
  else throw new Error("usage: release.cjs check <tag> | verify-updater <payload> <signature> | prepare <tag> <repo> <dir> <body> | bridge <old-dir> <release-dir> | verify-published <tag> <repo> <dir>");
}
module.exports = { checkVersions, compareVersions, assetNames, verifyUpdaterSignature, prepare, bridge };
