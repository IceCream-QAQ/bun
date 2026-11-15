import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Use the repository's public test certificate, not a deployment identity.
const harness = readFileSync(process.env.HARNESS_PATH || "/harness.ts", "utf8");
const fixture = harness.slice(harness.indexOf("export const tls = Object.freeze({"));
const tls = Object.fromEntries(
  ["cert", "key"].map(k => [k, JSON.parse(fixture.match(new RegExp(`${k}: ("[^"\\n]+")`))[1])]),
);
const h3 = { protocol: "http3", tls: { rejectUnauthorized: false } };
const sizeOf = (k, v) => k.length + v.length + 32;
const held = Promise.withResolvers();
const release = Promise.withResolvers();
let heldRequests = 0,
  postRequests = 0;
function cookiesOfSize(size) {
  const count = Math.floor(size / 43);
  const cookies = Array(count).fill("v");
  if (count) cookies[count - 1] += "v".repeat(size % 43);
  return cookies;
}
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  tls,
  http3: true,
  http1: false,
  async fetch(req) {
    const path = new URL(req.url).pathname;
    if (path === "/held") {
      heldRequests++;
      held.resolve();
      await release.promise;
      return new Response("held");
    }
    if (path === "/bad") {
      postRequests++;
      return new Response(null, { headers: { "x-large": "v".repeat(70_000) } });
    }
    if (path.startsWith("/cookies/")) {
      const headers = new Headers();
      for (const c of cookiesOfSize(Number(path.slice(9)))) headers.append("set-cookie", c);
      return new Response(null, { headers });
    }
    return Response.json(Object.fromEntries(req.headers));
  },
});
const request = (path = "/", init = {}) => fetch(new URL(path, server.url), { ...h3, ...init });
try {
  const base = await (await request()).json();
  const rest = Object.entries(base).reduce(
    (n, [k, v]) => n + sizeOf(k === "host" ? ":authority" : k, v),
    sizeOf(":method", "GET") + sizeOf(":scheme", "https") + sizeOf(":path", "/"),
  );
  const len = 16 * 1024 - rest - sizeOf("x-limit", "");
  let res = await request("/", { headers: { "x-limit": "v".repeat(len) } });
  assert.equal(res.status, 200);
  assert.equal((await res.json())["x-limit"].length, len);
  res = await request("/", { headers: { "x-limit": "v".repeat(len + 1) } });
  assert.equal(res.status, 431);
  assert.equal(await res.text(), "");
  const fields = Object.fromEntries(
    Array.from({ length: 200 - Object.keys(base).length - 3 }, (_, i) => [`x-${i}`, ""]),
  );
  res = await request("/", { headers: fields });
  assert.equal(res.status, 200);
  await res.text();
  res = await request("/", { headers: { ...fields, "x-extra": "" } });
  assert.equal(res.status, 431);
  await res.text();
  assert.deepEqual(await (await request()).json(), base);
  const other = request("/held");
  await held.promise;
  const empty = await request("/cookies/0");
  const overhead = [...empty.headers].reduce((n, [k, v]) => n + sizeOf(k, v), sizeOf(":status", "200"));
  await empty.text();
  const limit = 256 * 1024 - overhead;
  res = await request(`/cookies/${limit}`);
  assert.deepEqual(res.headers.getSetCookie(), cookiesOfSize(limit));
  await res.text();
  await assert.rejects(request(`/cookies/${limit + 1}`), { code: "ResponseHeadersTooLarge" });
  release.resolve();
  assert.equal(await (await other).text(), "held");
  assert.equal(heldRequests, 1);
  for (const method of ["POST", "PATCH"]) {
    const before = postRequests;
    await assert.rejects(request("/bad", { method, body: "do not replay" }), { code: "HTTP3StreamReset" });
    assert.equal(postRequests - before, 1);
  }
  assert.deepEqual(await (await request()).json(), base);
  console.log(
    JSON.stringify({
      http3:
        "PASS: request size/count boundaries, response boundary, independent stream, POST/PATCH no replay, recovery",
      version: Bun.version,
      revision: Bun.revision,
    }),
  );
} finally {
  release.resolve();
  server.stop(true);
}
