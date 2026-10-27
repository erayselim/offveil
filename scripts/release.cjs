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

// Beta builds never touch the stable update pointers. They publish their own
// manifest names, which installed 1.0.x clients do not look for, and a fixed
// prerelease carries the beta channel's Windows manifest.
const BETA_POINTER_TAG = "updates-beta";
const BETA_POINTER_ASSET = "latest-beta.json";

function isPrerelease(version) {
  return releaseVersion(version).split("+")[0].includes("-");
}

function manifestNames(version) {
  return isPrerelease(version)
    ? { windows: BETA_POINTER_ASSET, mac: "latest-mac-beta.json" }
    : { windows: "latest.json", mac: "latest-mac.json" };
}

function assetNames(version) {
  const prefix = `offveil_${version}`;
  const manifests = manifestNames(version);
  return [`${prefix}_x64-setup.exe`, `${prefix}_x64-setup.exe.sig`, `${prefix}_aarch64.dmg`,
    `${prefix}_aarch64.app.tar.gz`, `${prefix}_aarch64.app.tar.gz.sig`,
    manifests.windows, manifests.mac, "active.json", "active.json.sig",
    "sing-box-1.13.14-source.zip"];
}

// Build jobs always emit latest.json/latest-mac.json; prepare renames them for betas.
function buildOutputs(version) {
  const manifests = manifestNames(version);
  return assetNames(version).map((name) => name === manifests.windows ? "latest.json" : name === manifests.mac ? "latest-mac.json" : name);
}

function verifyPayloads(dir, tag, repo, pubkey, names = { windows: "latest.json", mac: "latest-mac.json" }) {
  const version = releaseVersion(tag);
  const base = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/`;
  const windows = readJSON(path.join(dir, names.windows));
  const mac = readJSON(path.join(dir, names.mac));
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
  for (const name of buildOutputs(version)) if (!fs.statSync(path.join(dir, name)).isFile()) throw new Error(`Missing ${name}`);
  const pubkey = readJSON(path.join(ROOT, "offveil-ui/src-tauri/tauri.conf.json")).plugins.updater.pubkey;
  const { windows, mac } = verifyPayloads(dir, tag, repo, pubkey);
  windows.platforms["darwin-aarch64"] = mac.platforms["darwin-aarch64"];
  windows.platforms["aarch64-apple-darwin"] = mac.platforms["darwin-aarch64"];
  json(path.join(dir, "latest.json"), windows);
  const names = manifestNames(version);
  if (names.windows !== "latest.json") {
    fs.renameSync(path.join(dir, "latest.json"), path.join(dir, names.windows));
    fs.renameSync(path.join(dir, "latest-mac.json"), path.join(dir, names.mac));
  }
  const sums = assetNames(version).map((name) => `${sha256(fs.readFileSync(path.join(dir, name)))}  ${name}`).join("\n") + "\n";
  fs.writeFileSync(path.join(dir, "SHA256SUMS.txt"), sums);
  const body = fs.readFileSync(path.join(ROOT, ".github/release-body.md"), "utf8")
    .replaceAll("{{VERSION}}", version).replaceAll("{{TAG}}", tag)
    .replaceAll("{{DOWNLOAD_BASE}}", `https://github.com/${repo}/releases/download/${tag}`);
  if (/\{\{\w+\}\}/.test(body)) throw new Error("Unresolved release body placeholder");
  fs.writeFileSync(bodyFile, body);
  return [...assetNames(version), "SHA256SUMS.txt"];
}

// The beta channel pointer receives every release's Windows manifest, so beta
// installs reach the next beta and, later, the stable release.
function betaPointer(releaseDir, outDir, tag) {
  const version = releaseVersion(tag);
  const source = path.join(releaseDir, manifestNames(version).windows);
  const doc = readJSON(source);
  if (doc.version !== version) throw new Error("Beta pointer manifest does not match the release");
  fs.mkdirSync(outDir, { recursive: true });
  fs.copyFileSync(source, path.join(outDir, BETA_POINTER_ASSET));
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
  const beta = isPrerelease(version);
  const { windows } = verifyPayloads(dir, tag, repo, currentKey, manifestNames(version));
  const windowsLive = JSON.parse(await fetchBytes(`https://github.com/${repo}/releases/latest/download/latest.json`));
  const betaLive = JSON.parse(await fetchBytes(`https://github.com/${repo}/releases/download/${BETA_POINTER_TAG}/${BETA_POINTER_ASSET}`));
  if (betaLive.version !== version || JSON.stringify(betaLive.platforms["windows-x86_64"]) !== JSON.stringify(windows.platforms["windows-x86_64"])) {
    throw new Error(`Beta channel pointer does not offer ${tag}`);
  }
  if (isPrerelease(windowsLive.version)) throw new Error("A beta reached the stable Windows update pointer");
  const releases = JSON.parse(await fetchBytes(`https://api.github.com/repos/${repo}/releases?per_page=100`)).filter((r) => {
    try { releaseVersion(r.tag_name); return true; } catch { return false; }
  });
  const sharedPriorVersions = ["v1.0.3", "v1.0.4-beta.1", "v1.0.4-beta.2", "v1.0.4-beta.3", "v1.0.4-beta.4"];
  for (const prior of ["v1.0.0-b4", "v1.0.0-b5", "v1.0.0-mac.3", "v1.0.0-mac.4", "v1.0.0", ...sharedPriorVersions]) {
    const old = JSON.parse(execFileSync("git", ["show", `${prior}:offveil-ui/src-tauri/tauri.conf.json`], { cwd: ROOT, encoding: "utf8" }));
    if (old.plugins.updater.pubkey !== currentKey || compareVersions(version, prior) <= 0) throw new Error(`Incompatible prior client ${prior}`);
    const windowsOffers = windowsLive.version === version &&
      JSON.stringify(windowsLive.platforms["windows-x86_64"]) === JSON.stringify(windows.platforms["windows-x86_64"]) &&
      old.plugins.updater.endpoints[0] === `https://github.com/${repo}/releases/latest/download/latest.json`;
    // Installed clients discover Mac updates by latest-mac.json only.
    const macCandidate = releases.filter((r) => !r.draft && compareVersions(r.tag_name, prior) > 0 &&
      ["latest-mac.json", `offveil_${releaseVersion(r.tag_name)}_aarch64.app.tar.gz`, `offveil_${releaseVersion(r.tag_name)}_aarch64.app.tar.gz.sig`]
        .every((name) => r.assets.some((a) => a.name === name && a.state === "uploaded"))
    ).sort((a, b) => compareVersions(b.tag_name, a.tag_name))[0];
    const macOffers = macCandidate?.tag_name === tag;
    if (beta) {
      if (windowsOffers || macOffers) throw new Error(`${prior} would be offered beta ${tag}`);
      console.log(`${prior}: beta ${tag} is not offered`);
      continue;
    }
    if (!prior.includes("-mac") && !windowsOffers) throw new Error(`${prior} Windows update endpoint does not offer ${tag}`);
    if ((prior.includes("-mac") || sharedPriorVersions.includes(prior)) && !macOffers) throw new Error(`${prior} Mac update discovery does not offer ${tag}`);
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
  else if (mode === "beta-pointer") betaPointer(args[0], args[1], args[2]);
  else if (mode === "verify-published") verifyPublished(args[0], args[1], args[2]).catch((err) => { console.error(err.message); process.exitCode = 1; });
  else throw new Error("usage: release.cjs check <tag> | verify-updater <payload> <signature> | prepare <tag> <repo> <dir> <body> | beta-pointer <release-dir> <out-dir> <tag> | verify-published <tag> <repo> <dir>");
}
module.exports = { checkVersions, compareVersions, assetNames, buildOutputs, manifestNames, isPrerelease, verifyUpdaterSignature, prepare, betaPointer, BETA_POINTER_TAG };
