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
const { isBrokenStatus, isLimitedStatus, connectionState } = exportsForTest;

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

test("automatic heal never maps its stopped/startup gap to protection off", () => {
  for (const state of ["stopping", "stopped", "starting", "active"]) {
    assert.equal(connectionState({ state, protection: state === "active", transition: "network_heal" }), "reconnecting");
  }
  assert.equal(connectionState({ state: "stopped", protection: false }), "off");
  assert.equal(connectionState({ state: "starting", protection: false }), "connecting");
});

test("local trial, gateway replacement, verified promote and demote map in order", () => {
  const local = {
    state: "degraded", protection: true, last_error: null,
    network: { mode: "local", coverage: "tls_http_only", healthy: true, reason: "remote_transport_unavailable" },
    tunnel: { up: true, retry_hint: true },
  };
  assert.equal(connectionState(local), "limited");
  assert.equal(connectionState({ ...local, transition: "transport_recovery" }), "limited");
  assert.equal(connectionState({ ...local, transition: "transport_recovery", tunnel: { up: false } }), "reconnecting");
  const remote = { ...local, state: "active", network: { mode: "remote", coverage: "public_tcp_udp_dual_stack", healthy: true } };
  assert.equal(connectionState(remote), "protected");
  assert.equal(connectionState({ ...remote, state: "degraded", last_error: "control quorum failed" }), "broken");
  assert.equal(connectionState({ ...remote, transition: "transport_recovery" }), "reconnecting");
  assert.equal(connectionState(local), "limited");
  assert.equal(connectionState({ state: "stopped", protection: false }), "off");
});
