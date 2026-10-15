const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { checkVersions, compareVersions, assetNames, verifyUpdaterSignature, bridge } = require("./release.cjs");

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

test("only required public assets are selected", () => {
  const names = assetNames("1.0.0-rc.1");
  assert.equal(new Set(names).size, 9);
  assert.ok(names.includes("active.json.sig"));
  assert.ok(names.includes("latest-mac.json"));
  assert.ok(names.includes("offveil_1.0.0-rc.1_aarch64.app.tar.gz.sig"));
  assert.ok(!names.includes("READ-ME-FIRST.txt"));
});

test("legacy bridge changes only the update pointer and its checksum", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "offveil-release-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const legacy = path.join(dir, "legacy"), next = path.join(dir, "next");
  fs.mkdirSync(legacy); fs.mkdirSync(next);
  const installerHash = "a".repeat(64);
  fs.writeFileSync(path.join(legacy, "latest.json"), JSON.stringify({ version: "1.0.0-b5" }));
  fs.writeFileSync(path.join(legacy, "SHA256SUMS.txt"), `${installerHash}  old-setup.exe\n${"b".repeat(64)}  latest.json\n`);
  const manifest = JSON.stringify({ version: "1.0.0-rc.1", platforms: { "windows-x86_64": { signature: "signed", url: "https://github.com/rc/setup.exe" } } });
  fs.writeFileSync(path.join(next, "latest.json"), manifest);
  bridge(legacy, next);
  assert.equal(fs.readFileSync(path.join(legacy, "latest.json"), "utf8"), manifest);
  const sums = fs.readFileSync(path.join(legacy, "SHA256SUMS.txt"), "utf8");
  assert.ok(sums.includes(`${installerHash}  old-setup.exe`));
  const hash = crypto.createHash("sha256").update(manifest).digest("hex");
  assert.ok(sums.includes(`${hash}  latest.json`));
  assert.equal(sums.split("latest.json").length, 2);
  fs.writeFileSync(path.join(next, "latest.json"), JSON.stringify({ version: "1.0.0-b4" }));
  assert.throws(() => bridge(legacy, next), /advance/);
  assert.equal(fs.readFileSync(path.join(legacy, "latest.json"), "utf8"), manifest);
});
