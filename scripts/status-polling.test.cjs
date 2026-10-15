const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("../offveil-ui/node_modules/typescript");

// Exercise the real hook's timer/native-event lifecycle without a WebKit host.
const source = ts.transpileModule(
  fs.readFileSync(path.join(__dirname, "../offveil-ui/src/use-status-polling.ts"), "utf8"),
  { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } },
).outputText;
const flush = () => new Promise((resolve) => setImmediate(resolve));

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness({ visible = true, refresh = async () => {}, visibility } = {}) {
  let now = 0, nextID = 0, calls = 0, cleanup;
  const timers = new Map();
  const native = new Map();
  const documentEvents = new Map();
  const document = {
    hidden: false,
    addEventListener: (event, fn) => documentEvents.set(event, fn),
    removeEventListener: (event) => documentEvents.delete(event),
  };
  const register = (event, fn) => {
    native.set(event, fn);
    return Promise.resolve(() => native.delete(event));
  };
  const win = {
    isVisible: visibility || (() => Promise.resolve(visible)),
    onFocusChanged: (fn) => register("focus", fn),
  };
  const exports = {};
  vm.runInNewContext(source, {
    exports,
    require: (name) => {
      if (name === "react") return { useEffect: (effect) => { cleanup = effect(); } };
      if (name === "@tauri-apps/api/event") return { listen: register };
      if (name === "@tauri-apps/api/window") return { getCurrentWindow: () => win };
      throw new Error(`Unexpected import ${name}`);
    },
    document,
    window: {
      setTimeout: (fn, delay) => {
        const id = ++nextID;
        timers.set(id, { fn, at: now + delay });
        return id;
      },
      clearTimeout: (id) => timers.delete(id),
    },
  });
  exports.useStatusPolling(true, () => { calls++; return refresh(); });
  return {
    get calls() { return calls; },
    get timers() { return timers.size; },
    get listeners() { return native.size + documentEvents.size; },
    emit: (event, payload) => native.get(event)?.({ payload }),
    cleanup: () => cleanup?.(),
    async advance(ms) {
      const target = now + ms;
      for (let iterations = 0; ; iterations++) {
        assert.ok(iterations < 1000, "timer loop failed to settle");
        const next = [...timers].filter(([, timer]) => timer.at <= target)
          .sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        const [id, timer] = next;
        now = timer.at;
        timers.delete(id);
        timer.fn();
        await flush();
      }
      now = target;
      await flush();
    },
  };
}

test("hidden tray window polls slowly and reveal refreshes immediately", async (t) => {
  const h = harness({ visible: false });
  t.after(h.cleanup);
  await flush();
  await h.advance(29_999);
  assert.equal(h.calls, 0);
  await h.advance(1);
  assert.equal(h.calls, 1);
  h.emit("window-revealing");
  await flush();
  assert.equal(h.calls, 2);
  await h.advance(2500);
  assert.equal(h.calls, 3);
});

test("slow status request cannot overlap even across hide/reveal", async (t) => {
  const pending = deferred();
  let active = 0, maxActive = 0;
  const h = harness({ refresh: async () => {
    active++;
    maxActive = Math.max(maxActive, active);
    await pending.promise;
    active--;
  } });
  t.after(h.cleanup);
  await flush();
  await h.advance(2500);
  h.emit("window-dismissing");
  await h.advance(30_000);
  h.emit("window-revealing");
  assert.equal(h.calls, 1);
  pending.resolve();
  await flush();
  await h.advance(0);
  assert.equal(h.calls, 2);
  assert.equal(maxActive, 1);
});

test("cleanup removes events and late requests cannot restart polling", async () => {
  const pending = deferred();
  const h = harness({ refresh: () => pending.promise });
  await flush();
  await h.advance(2500);
  h.cleanup();
  pending.resolve();
  await flush();
  await h.advance(60_000);
  assert.equal(h.calls, 1);
  assert.equal(h.timers, 0);
  assert.equal(h.listeners, 0);
});

for (const rejected of [false, true]) {
  test(`late native visibility ${rejected ? "error" : "response"} cannot undo a tray hide`, async (t) => {
    const pending = deferred();
    const h = harness({ visibility: () => pending.promise });
    t.after(h.cleanup);
    h.emit("window-dismissing");
    if (rejected) pending.reject(new Error("native window unavailable"));
    else pending.resolve(true);
    await flush();
    await h.advance(2500);
    assert.equal(h.calls, 0);
    await h.advance(27_500);
    assert.equal(h.calls, 1);
  });
}
