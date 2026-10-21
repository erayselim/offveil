const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("../offveil-ui/node_modules/typescript");
const source = ts.transpileModule(
  fs.readFileSync(path.join(__dirname, "../offveil-ui/src/connection-status.ts"), "utf8"),
  { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } },
).outputText;
const exportsForTest = {};
vm.runInNewContext(source, { exports: exportsForTest });
const { isBrokenStatus, isLimitedStatus } = exportsForTest;

test("local fallback stays visibly limited while the provider retries", () => {
  const status = {
    protection: true, state: "degraded", last_error: null,
    network: { mode: "local", coverage: "tls_http_only", healthy: true, reason: "remote_transport_unavailable" },
    tunnel: { retry_hint: true },
  };
  assert.equal(isLimitedStatus(status), true);
  assert.equal(isBrokenStatus(status), false);
});

test("a failed required component or repeated control failure is broken", () => {
  for (const reason of ["component_unavailable", "control_quorum_failed"]) {
    const status = { protection: true, state: "degraded", network: { mode: "local", coverage: "tls_http_only", healthy: false, reason } };
    assert.equal(isLimitedStatus(status), false);
    assert.equal(isBrokenStatus(status), true);
  }
});

test("one transient control round cannot override the core's accepted remote route", () => {
  assert.equal(isBrokenStatus({ protection: true, state: "active", network: { mode: "remote", coverage: "public_tcp_udp_dual_stack", healthy: false }, tunnel: { retry_hint: true } }), false);
});

test("stopped protection ignores retained provider errors", () => {
  assert.equal(isBrokenStatus({ protection: false, state: "stopped", last_error: "old error", tunnel: { retry_hint: true } }), false);
});

test("legacy daemon errors remain visible without the additive network field", () => {
  assert.equal(isBrokenStatus({ protection: true, state: "active", tunnel: { retry_hint: true } }), true);
});
