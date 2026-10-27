const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { checkVersions, compareVersions, assetNames, buildOutputs, manifestNames, verifyUpdaterSignature, betaPointer } = require("./release.cjs");

function signed(bytes, prehashed = true) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const rawKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const id = crypto.randomBytes(8);
  const pub = `untrusted comment: test key\n${Buffer.concat([Buffer.from("Ed"), id, rawKey]).toString("base64")}\n`;
  const payload = prehashed ? crypto.createHash("blake2b512").update(bytes).digest() : bytes;
  const sig = crypto.sign(null, payload, privateKey);
  const comment = "timestamp:1\tfile:test.app.tar.gz";
  const global = crypto.sign(null, Buffer.concat([sig, Buffer.from(comment)]), privateKey);
  const packet = Buffer.concat([Buffer.from(prehashed ? "ED" : "Ed"), id, sig]);
  const text = `untrusted comment: signature\n${packet.toString("base64")}\ntrusted comment: ${comment}\n${global.toString("base64")}\n`;
  return { signature: Buffer.from(text).toString("base64"), pubkey: Buffer.from(pub).toString("base64") };
}

test("all app, core, release-note and lock versions agree", () => {
  const version = require("../offveil-ui/package.json").version;
  assert.equal(checkVersions(`v${version}`), version);
  assert.throws(() => checkVersions("v99.0.0"), /mismatch/i);
});

test("shared RC upgrades the last two Windows and Mac versions", () => {
  for (const prior of ["1.0.0-b4", "1.0.0-b5", "1.0.0-mac.3", "1.0.0-mac.4"]) {
    assert.ok(compareVersions("v1.0.0-rc.1", prior) > 0);
  }
  assert.ok(compareVersions("1.0.0", "1.0.0-rc.1") > 0);
  assert.ok(compareVersions("1.0.0-rc.10", "1.0.0-rc.2") > 0);
  assert.equal(compareVersions("1.0.0+one", "v1.0.0+two"), 0);
  assert.throws(() => compareVersions("ruleset-latest", "1.0.0"));
});

test("patch release upgrades the current stable version", () => {
  assert.ok(compareVersions("1.0.1", "1.0.0") > 0);
  assert.ok(compareVersions("1.0.0", "1.0.1") < 0);
});

test("1.0.4 beta upgrades stable and can advance to the final release", () => {
  assert.ok(compareVersions("1.0.4-beta.1", "1.0.3") > 0);
  assert.ok(compareVersions("1.0.4-beta.2", "1.0.4-beta.1") > 0);
  assert.ok(compareVersions("1.0.4-beta.3", "1.0.4-beta.2") > 0);
  assert.ok(compareVersions("1.0.4-beta.4", "1.0.4-beta.3") > 0);
  assert.ok(compareVersions("1.0.4", "1.0.4-beta.1") > 0);
  assert.ok(compareVersions("1.0.4", "1.0.4-beta.2") > 0);
  assert.ok(compareVersions("1.0.4", "1.0.4-beta.3") > 0);
  assert.ok(compareVersions("1.0.4", "1.0.4-beta.4") > 0);
});

for (const prehashed of [true, false]) {
  test(`updater signatures verify payload and trusted comment (${prehashed ? "ED" : "Ed"})`, () => {
    const bytes = Buffer.from("release installer bytes");
    const { signature, pubkey } = signed(bytes, prehashed);
    verifyUpdaterSignature(bytes, signature, pubkey);
    assert.throws(() => verifyUpdaterSignature(Buffer.from("tampered installer"), signature, pubkey));
    const changed = Buffer.from(signature, "base64").toString("utf8").replace("timestamp:1", "timestamp:2");
    assert.throws(() => verifyUpdaterSignature(bytes, Buffer.from(changed).toString("base64"), pubkey));
    assert.throws(() => verifyUpdaterSignature(bytes, signature, signed(bytes).pubkey));
  });
}

test("1.1.0 betas follow every 1.0.x build and precede the final", () => {
  for (const prior of ["1.0.3", "1.0.4-beta.4", "1.0.4-beta.4.1"]) assert.ok(compareVersions("1.1.0-beta.1", prior) > 0);
  assert.ok(compareVersions("1.1.0-beta.2", "1.1.0-beta.1") > 0);
  assert.ok(compareVersions("1.1.0", "1.1.0-beta.9") > 0);
});

test("stable releases publish stable manifests", () => {
  const names = assetNames("1.1.0");
  assert.equal(new Set(names).size, 10);
  assert.ok(names.includes("sing-box-1.13.14-source.zip"));
  assert.ok(names.includes("active.json.sig"));
  assert.ok(names.includes("latest.json") && names.includes("latest-mac.json"));
  assert.ok(names.includes("offveil_1.1.0_aarch64.app.tar.gz.sig"));
  assert.ok(!names.includes("READ-ME-FIRST.txt"));
  assert.deepEqual(buildOutputs("1.1.0"), names);
});

test("betas never publish a manifest that installed stable clients read", () => {
  const names = assetNames("1.1.0-beta.1");
  assert.ok(!names.includes("latest.json") && !names.includes("latest-mac.json"));
  assert.ok(names.includes("latest-beta.json") && names.includes("latest-mac-beta.json"));
  assert.deepEqual(manifestNames("1.1.0-beta.1"), { windows: "latest-beta.json", mac: "latest-mac-beta.json" });
  const built = buildOutputs("1.1.0-beta.1");
  assert.ok(built.includes("latest.json") && built.includes("latest-mac.json"));
});

test("the beta pointer copies the release's Windows manifest", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "offveil-release-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const out = path.join(dir, "pointer");
  const manifest = JSON.stringify({ version: "1.1.0-beta.1", platforms: { "windows-x86_64": { signature: "s", url: "u" } } });
  fs.writeFileSync(path.join(dir, "latest-beta.json"), manifest);
  betaPointer(dir, out, "v1.1.0-beta.1");
  assert.equal(fs.readFileSync(path.join(out, "latest-beta.json"), "utf8"), manifest);
  const stable = JSON.stringify({ version: "1.1.0", platforms: {} });
  fs.writeFileSync(path.join(dir, "latest.json"), stable);
  betaPointer(dir, out, "v1.1.0");
  assert.equal(fs.readFileSync(path.join(out, "latest-beta.json"), "utf8"), stable);
  assert.throws(() => betaPointer(dir, out, "v1.1.1"), /does not match/);
});
