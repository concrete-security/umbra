const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function drawer(pending = []) {
  const admin = {
    P: { CVM_MANAGE: "manage", USER_MANAGE: "users", PERM_MANAGE: "permissions" },
    has: () => true,
    canActOnCvms: () => true,
    isHomeEntity: () => true,
    viewEntityId: () => "entity-fixture",
    Ops: { pendingForCvm: () => pending },
    api: async () => ({ ok: true, json: async () => ({ items: [] }) }),
  };
  const context = vm.createContext({
    window: { Admin: admin },
    document: { readyState: "loading", addEventListener() {} },
  });
  for (const name of ["ui.js", "drawer.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../static/admin", name), "utf8"), context);
  }
  return admin.Drawer;
}

// Attribute boundaries must hold even when an API/storage value is malformed.
test("profile attributes escape injected quotes and markup", async () => {
  const html = await drawer().renderCvmActions({
    id: "cvm-fixture", state: "running", profiles: [{ id: '\" autofocus onfocus=\"fixture', name: "profile-fixture" }],
  });
  assert.ok(html.includes('data-detach="&quot; autofocus onfocus=&quot;fixture"'));
  assert.ok(!html.includes('data-detach="" autofocus'));
  assert.ok(html.includes("profile-fixture"));
});

// Browser storage is not an HTML trust boundary, including stale pending records.
test("pending operation kinds remain text", async () => {
  const html = await drawer([{ kind: "<img src=x onerror=fixture>" }, { kind: "cvm.update" }])
    .renderCvmSummary({ id: "cvm-fixture", state: "stopped", profiles: [] });
  assert.ok(html.includes("&lt;img src=x onerror=fixture&gt;, cvm.update"));
  assert.ok(!html.includes("<img src=x"));
});
