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
vm.runInNewContext(source, { exports: exportsForTest, Set });
const { isBrokenStatus, isLimitedStatus, isOfflineStatus, connectionState } = exportsForTest;

const selective = (extra = {}) => ({
  state: "active", protection: true, last_error: null,
  network: { mode: "selective", coverage: "dns_web_desync", healthy: true, layers: { dns: "up", tcp: "up", tunnel: "off" } },
  tunnel: { up: true },
  ...extra,
});

test("healthy layers are protected", () => {
  assert.equal(connectionState(selective()), "protected");
  assert.equal(connectionState(selective({ network: { mode: "dns_only", coverage: "dns", healthy: true } })), "protected");
});

test("DNS-only fallback and an unreachable group are limited, not broken", () => {
  for (const reason of ["dns_only_fallback", "group_unreachable"]) {
    const status = selective({ network: { mode: "fallback", coverage: "dns", healthy: false, reason } });
    assert.equal(isLimitedStatus(status), true);
    assert.equal(isBrokenStatus(status), false);
    assert.equal(connectionState(status), "limited");
  }
});

test("a missing internet connection is offline, not broken", () => {
  const status = selective({ network: { mode: "selective", coverage: "dns_web_desync", healthy: false, reason: "offline" } });
  assert.equal(isOfflineStatus(status), true);
  assert.equal(isBrokenStatus(status), false);
  assert.equal(connectionState(status), "offline");
});

test("only a dead resolver or exhausted recovery is broken", () => {
  for (const reason of ["dns_unavailable", "component_unavailable"]) {
    const status = selective({ state: "degraded", last_error: "dns: local resolver stopped", network: { mode: "selective", coverage: "dns", healthy: false, reason } });
    assert.equal(isBrokenStatus(status), true);
    assert.equal(connectionState(status), "broken");
  }
});

test("component recovery in progress reads as reconnecting", () => {
  const status = selective({ transition: "transport_recovery", network: { mode: "selective", coverage: "dns_web_desync", healthy: false, reason: "recovering" } });
  assert.equal(connectionState(status), "reconnecting");
});

test("a group switch keeps a limited path visibly limited", () => {
  const limited = selective({ network: { mode: "selective", coverage: "dns_web_desync", healthy: false, reason: "group_unreachable" } });
  assert.equal(connectionState({ ...limited, transition: "transport_recovery" }), "limited");
  assert.equal(connectionState({ ...limited, transition: "transport_recovery", tunnel: { up: false } }), "reconnecting");
});

test("stopped protection ignores retained errors", () => {
  assert.equal(isBrokenStatus({ protection: false, state: "stopped", last_error: "old error", tunnel: { retry_hint: true } }), false);
  assert.equal(connectionState({ state: "stopped", protection: false }), "off");
});

test("legacy cores keep their meaning", () => {
  assert.equal(isBrokenStatus({ protection: true, state: "active", tunnel: { retry_hint: true } }), true);
  const local = {
    state: "degraded", protection: true, last_error: null,
    network: { mode: "local", coverage: "tls_http_only", healthy: true, reason: "remote_transport_unavailable" },
    tunnel: { up: true, retry_hint: true },
  };
  assert.equal(connectionState(local), "limited");
  assert.equal(connectionState({ ...local, network: { ...local.network, reason: "control_quorum_failed" }, last_error: "x" }), "broken");
});

test("automatic heal never maps its stopped/startup gap to protection off", () => {
  for (const state of ["stopping", "stopped", "starting", "active"]) {
    assert.equal(connectionState({ state, protection: state === "active", transition: "network_heal" }), "reconnecting");
  }
  assert.equal(connectionState({ state: "starting", protection: false }), "connecting");
});
