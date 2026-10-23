import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createClient, getCvmComposeFile, listAllInstanceTypeFamilies } from "@phala/cloud";
import { z } from "zod";

const execute = promisify(execFile);
const consoleRoot = fileURLToPath(new URL("../", import.meta.url));
const cli = path.join(consoleRoot, "node_modules/phala/dist/index.js");
const appId = "a".repeat(40);
const apiVersion = "2026-05-22";

async function cliEnvironment(t) {
  const home = await mkdtemp(path.join(tmpdir(), "umbra-phala-test-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  return { PATH: process.env.PATH, HOME: home, LANG: "C.UTF-8" };
}

async function mockProvider(t, payload) {
  const requests = [];
  const server = createServer((request, response) => {
    requests.push({ method: request.method, path: request.url, apiVersion: request.headers["x-phala-version"] });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(payload));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  return { baseURL: `http://127.0.0.1:${server.address().port}`, requests };
}

// Phala 1.1.19 imported removed v3 internals and failed before command dispatch.
test("test_phala_version_with_fixed_zod_success", async t => {
  const manifest = JSON.parse(await readFile(path.join(consoleRoot, "node_modules/phala/package.json"), "utf8"));
  const { stdout } = await execute(process.execPath, [cli, "--version"], {
    cwd: consoleRoot, env: await cliEnvironment(t), timeout: 5000,
  });
  assert.ok(stdout.startsWith(`v${manifest.version}+`));
});

for (const command of [[], ["deploy"], ["instance-types"], ...["get", "list", "logs", "start", "stop", "delete"].map(verb => ["cvms", verb])]) {
  // Every verb invoked by the adapter must load with the overridden Zod runtime.
  test(`test_phala_${command.join("_") || "root"}_help_success`, async t => {
    const { stdout } = await execute(process.execPath, [cli, ...command, "--help"], {
      cwd: consoleRoot, env: await cliEnvironment(t), timeout: 5000,
    });
    assert.match(stdout, /Usage:/);
    const flags = command[0] === "deploy"
      ? ["--name", "--compose", "--cvm-id", "--wait", "--json", "--no-dev-os", "--disk-size", "--image", "--instance-type", "--region", "--env"]
      : command[1] === "delete" ? ["--force"] : ["get", "list"].includes(command[1]) ? ["--json"] : [];
    for (const flag of flags) assert.ok(stdout.includes(flag), `Missing adapter option ${flag}`);
  });
}

for (const [name, schema, input] of [
  ["array_max", element => z.array(element).max(2), Array(16).fill(0)],
  ["array_length", element => z.array(element).length(2), Array(16).fill(0)],
  ["set_max", element => z.set(element).max(2), new Set(Array.from({ length: 16 }, (_, index) => index))],
  ["map_max", element => z.map(element, element).max(2), new Map(Array.from({ length: 16 }, (_, index) => [index, index]))],
]) {
  // CVE-2023-54404 must reject excess size before allocating per-element issues.
  test(`test_oversized_${name}_rejected_before_elements_failure`, () => {
    let visits = 0;
    const element = z.preprocess(value => { visits += 1; return value; }, z.string());
    const result = schema(element).safeParse(input);
    assert.deepEqual({ visits, codes: result.error.issues.map(issue => issue.code) }, { visits: 0, codes: ["too_big"] });
  });
}

// The real SDK still accepts the captured catalog consumed by the adapter.
test("test_phala_catalog_fixture_success", async t => {
  const fixture = JSON.parse(await readFile(new URL("fixtures/phala_instance_types.json", import.meta.url), "utf8"));
  const payload = { result: fixture.result };
  const { baseURL } = await mockProvider(t, payload);
  const client = createClient({ baseURL, apiKey: "offline-test-key", version: apiVersion, retry: 0 });
  assert.deepEqual(await listAllInstanceTypeFamilies(client), payload);
});

// The compose helper deliberately requests raw provider data and hashes only YAML.
test("test_phala_compose_raw_sdk_success", async t => {
  const payload = { docker_compose_file: "services: {}\n", allowed_envs: [42] };
  const { baseURL, requests } = await mockProvider(t, payload);
  const client = createClient({ baseURL, apiKey: "offline-test-key", version: apiVersion, retry: 0 });
  const result = await getCvmComposeFile(client, { app_id: appId }, { schema: false });
  assert.deepEqual({ result, requests }, {
    result: payload, requests: [{ method: "GET", path: `/cvms/app_${appId}/compose_file`, apiVersion }],
  });
});

// Run the adapter's actual embedded helper against the real SDK and loopback API.
test("test_phala_compose_hash_helper_success", async t => {
  const compose = "services:\n  app:\n    image: example.invalid/test:1\n";
  const { baseURL, requests } = await mockProvider(t, { docker_compose_file: compose });
  const source = await readFile(path.join(consoleRoot, "src/umbra_console/tee_provider/phala.py"), "utf8");
  const helper = source.match(/PHALA_COMPOSE_FILE_HASH_HELPER = r"""\n([\s\S]*?)"""/)[1];
  const { stdout } = await execute(process.execPath, ["--input-type=module", "-e", helper, `app_0x${appId.toUpperCase()}`], {
    cwd: consoleRoot,
    env: { ...await cliEnvironment(t), PHALA_CLOUD_API_PREFIX: baseURL, PHALA_CLOUD_API_KEY: "offline-test-key" },
    timeout: 5000,
  });
  assert.deepEqual({ result: JSON.parse(stdout), requests }, {
    result: { sha256: createHash("sha256").update(compose).digest("hex") },
    requests: [{ method: "GET", path: `/cvms/app_${appId}/compose_file`, apiVersion }],
  });
});

// Exercise the real CLI response schema used by info, status and update lookups.
test("test_phala_cvm_get_json_success", async t => {
  const payload = {
    id: "cvm-fixture", name: "umbra-v0-cvm-fixture", app_id: appId,
    status: "running", resource: {}, gateway: { base_domain: "gateway.example.com" },
    services: [{ name: "app", image: "example.invalid/test:1" }],
    compose_file: { services: { app: { image: "example.invalid/test:1" } } },
  };
  const { baseURL, requests } = await mockProvider(t, payload);
  const { stdout } = await execute(process.execPath, [cli, "cvms", "get", appId, "--json", "--api-version", apiVersion], {
    cwd: consoleRoot,
    env: { ...await cliEnvironment(t), PHALA_CLOUD_API_PREFIX: baseURL, PHALA_CLOUD_API_KEY: "offline-test-key" },
    timeout: 5000,
  });
  const info = JSON.parse(stdout);
  assert.deepEqual({
    app_id: info.app_id, status: info.status, gateway: info.gateway,
    services: info.services, compose_file: info.compose_file, requests,
  }, {
    app_id: appId, status: "running", gateway: payload.gateway,
    services: payload.services, compose_file: payload.compose_file,
    requests: [{ method: "GET", path: `/cvms/app_${appId}`, apiVersion }],
  });
});

// The CLI's JSON catalog envelope must remain compatible with the Python parser.
test("test_phala_catalog_cli_json_success", async t => {
  const fixture = JSON.parse(await readFile(new URL("fixtures/phala_instance_types.json", import.meta.url), "utf8"));
  const { baseURL } = await mockProvider(t, { result: fixture.result });
  const { stdout } = await execute(process.execPath, [cli, "instance-types", "--json", "--api-version", apiVersion], {
    cwd: consoleRoot,
    env: { ...await cliEnvironment(t), PHALA_CLOUD_API_PREFIX: baseURL, PHALA_CLOUD_API_KEY: "offline-test-key" },
    timeout: 5000,
  });
  assert.deepEqual(JSON.parse(stdout), fixture);
});
