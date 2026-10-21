const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { releaseVersion, releaseNotes, manifest } = require("./mac-release.cjs");

test("Mac protection acceptance distinguishes verified remote and limited local paths", () => {
  const script = fs.readFileSync(path.join(__dirname, "darwin-smoke-install.sh"), "utf8");
  const code = /assert_protection_ready\(\) \{\r?\nnode - "\$1" <<'NODE'\r?\n([\s\S]*?)\r?\nNODE/.exec(script)?.[1];
  assert.ok(code, "actual installer smoke assertion must be tested");
  const base = { protection: true, tunnel: { up: true }, desync: { up: true }, dns: { stub_up: true }, last_error: null };
  const check = (status) => vm.runInNewContext(code, {
    require: () => ({ readFileSync: () => JSON.stringify({ ok: true, result: { ...base, ...status } }) }),
    process: { argv: ["node", "-", "fixture.json"] }, console: { log() {} },
  });
  const remote = { state: "active", network: { mode: "remote", healthy: true, coverage: "public_tcp_udp_dual_stack", udp_path: "tunnel" } };
  const local = { state: "degraded", network: { mode: "local", healthy: true, coverage: "tls_http_only", udp_path: "direct", reason: "remote_transport_unavailable" } };
  assert.doesNotThrow(() => check(remote));
  assert.doesNotThrow(() => check(local));
  assert.throws(() => check({ ...remote, network: { ...remote.network, healthy: false } }));
  assert.throws(() => check({ ...local, network: { ...local.network, reason: "control_quorum_failed" } }));
  assert.throws(() => check({ ...local, tunnel: { up: false } }));
  assert.throws(() => check({ ...local, state: "active" }));
});

test("release tags become distinct application versions", () => {
  for (const tag of ["v1.0.0-mac.9", "v1.0.0-mac.10", "v1.0.0", "v1.1.0-beta.2+build.3"]) {
    assert.equal(releaseVersion(tag), tag.slice(1));
  }
  for (const tag of ["main", "v1.0.0-mac.01", "v01.0.0", "v1.0", "v1.0.0-a b"]) {
    assert.throws(() => releaseVersion(tag));
  }
});
test("manifest carries the final archive's signature and immutable tag URL", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "offveil-manifest-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const tar = path.join(dir, "offveil_1.0.0-mac.10_aarch64.app.tar.gz");
  fs.writeFileSync(tar, "sealed archive");
  fs.writeFileSync(`${tar}.sig`, "signature-content\n");
  const doc = manifest({ tag: "v1.0.0-mac.10", repo: "erayselim/offveil", tar });
  assert.equal(doc.version, "1.0.0-mac.10");
  assert.deepEqual(Object.keys(doc.platforms), ["darwin-aarch64"]);
  assert.equal(doc.platforms["darwin-aarch64"].signature, "signature-content");
  assert.equal(doc.platforms["darwin-aarch64"].url, "https://github.com/erayselim/offveil/releases/download/v1.0.0-mac.10/offveil_1.0.0-mac.10_aarch64.app.tar.gz");
  fs.writeFileSync(`${tar}.sig`, " ");
  assert.throws(() => manifest({ tag: "v1.0.0-mac.10", repo: "erayselim/offveil", tar }));
});

test("Windows and Mac notes use the same release version", () => {
  const mac = JSON.parse(fs.readFileSync(path.join(__dirname, "../offveil-ui/src/whats-new.macos.json"), "utf8"));
  assert.deepEqual(releaseNotes(`v${mac.version}`), mac.notes);
  assert.equal(releaseNotes("v99.0.0"), null);
  const windows = JSON.parse(fs.readFileSync(path.join(__dirname, "../offveil-ui/src/whats-new.json"), "utf8"));
  assert.equal(windows.version, mac.version);
});
