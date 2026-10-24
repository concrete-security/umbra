/*
 * Exercise npm node-gyp's resolved Undici over in-container loopback.
 *
 * Run from the repository root against a selected image:
 *   docker run --rm -i --network none --platform linux/amd64 \
 *     --entrypoint node "$IMAGE" - < cvms/dev/tests/npm_undici_smoke.cjs
 *
 * CVE-2026-109869: six content codings plus an early close crashed Undici
 * 6.29.0 through an unhandled internal stream error, even when fetch rejected.
 * Keep unhandled exceptions fatal so the test detects an orphaned stream crash.
 */
"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const { createRequire } = require("node:module");
const { statSync } = require("node:fs");
const caller = "/usr/local/lib/node_modules/npm/node_modules/node-gyp/lib/download.js";
assert.ok(statSync(caller).isFile(), "npm's node-gyp download caller must exist");
const callerRequire = createRequire(caller);
assert.equal(
  callerRequire.resolve("undici"),
  "/usr/local/lib/node_modules/npm/node_modules/undici/index.js",
);
const undici = callerRequire("undici");
const version = callerRequire("undici/package.json").version;
assert.equal(version, "6.29.1");
const deadline = setTimeout(() => {
  console.error("Undici loopback check timed out");
  process.exit(1);
}, 5000);

const server = http.createServer((request, response) => {
  if (request.url === "/oversized-encoding") {
    response.writeHead(200, {
      "Content-Encoding": "gzip, deflate, br, gzip, deflate, br",
      "Content-Length": "1",
      "Connection": "close",
    });
    response.flushHeaders();
    response.end();
  } else {
    response.writeHead(200, {
      "Content-Type": "text/plain",
      "Connection": "close",
    });
    response.end("healthy");
  }
});

(async () => {
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(undici.fetch(origin + "/oversized-encoding"));
  await new Promise(resolve => setTimeout(resolve, 100));
  const response = await undici.fetch(origin + "/healthy");
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "healthy");
  console.log(
    `Installed npm Undici ${version}: malformed response rejected; process survived; normal request passed`,
  );
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  clearTimeout(deadline);
})().catch(error => {
  console.error(error.message);
  process.exit(1);
});
