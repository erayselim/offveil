const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { releaseVersion, manifest } = require("./mac-release.cjs");

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
