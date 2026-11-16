import {
  addBlockedSPKIForTesting,
  clearBlockedSPKIsForTesting,
  addBlockedCertificateForTesting,
  clearBlockedCertificatesForTesting,
  certificateBlockedErrorForTesting,
} from "bun:internal-for-testing";
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";

// Exact identities removed by the upstream trust-store backport. This check is
// deliberately not a blanket name match: unrelated roots must remain usable.
const removedRoots = new Set([
  "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b", // emSign ECC G3
  "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f", // emSign C1
  "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3", // emSign ECC C3
]);
assert(tls.rootCertificates.length > 100, "default trust store must not be empty");
for (const pem of tls.rootCertificates) {
  const fingerprint = new X509Certificate(pem).fingerprint256.replaceAll(":", "").toLowerCase();
  assert(!removedRoots.has(fingerprint), `removed root still bundled: ${fingerprint}`);
}

// Exercise the compiled production matcher against all primary and cross-signed
// public certificates. Matching DER and SPKI hashes also guards fixture drift.
const emsignDir = process.env.EMSIGN_FIXTURES_PATH || "/emsign";
const manifest = JSON.parse(readFileSync(`${emsignDir}/manifest.json`, "utf8"));
assert.equal(manifest.length, 32, "all 32 primary/cross-signed certificates are required");
assert.equal(new Set(manifest.map(entry => entry.cert_sha256)).size, 32);
assert.equal(manifest.filter(entry => entry.policy === "certificate DER SHA-256").length, 16);
assert.equal(manifest.filter(entry => entry.policy === "SPKI SHA-256").length, 16);
for (const entry of manifest) {
  const pem = readFileSync(`${emsignDir}/${entry.file}`, "utf8");
  const cert = new X509Certificate(pem);
  assert.equal(createHash("sha256").update(cert.raw).digest("hex"), entry.cert_sha256, entry.file);
  assert.equal(
    createHash("sha256")
      .update(cert.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex"),
    entry.spki_sha256,
    entry.file,
  );
  assert.equal(entry.expected_error, 23, entry.file);
  assert.equal(
    certificateBlockedErrorForTesting(pem),
    23,
    `${entry.file}: production matcher must return CERT_REVOKED`,
  );
}

// Public repository fixture only. No external network or deployment identity.
const harness = readFileSync(process.env.HARNESS_PATH || "/harness.ts", "utf8");
const fixture = harness.slice(harness.indexOf("export const tls = Object.freeze({"));
const identity = Object.fromEntries(
  ["cert", "key"].map(k => [k, JSON.parse(fixture.match(new RegExp(`${k}: ("[^"\\n]+")`))[1])]),
);
async function checkHTTP3(mode) {
  const directory = mkdtempSync(join(tmpdir(), "bun-tls-smoke-"));
  const certPath = join(directory, "ca.pem");
  writeFileSync(certPath, identity.cert);
  const h3Server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    tls: identity,
    http3: true,
    http1: false,
    fetch: () => new Response("verified HTTP3 TLS"),
  });
  let child;
  let timer;
  try {
    const env = { ...process.env, BUN_FEATURE_FLAG_INTERNAL_FOR_TESTING: "1", BUN_GARBAGE_COLLECTOR_LEVEL: "0" };
    delete env.NODE_EXTRA_CA_CERTS;
    delete env.SSL_CERT_FILE;
    delete env.SSL_CERT_DIR;
    delete env.NODE_TLS_REJECT_UNAUTHORIZED;
    if (mode !== "untrusted") env.NODE_EXTRA_CA_CERTS = certPath;
    const code = `
      import { addBlockedSPKIForTesting, addBlockedCertificateForTesting } from "bun:internal-for-testing";
      import { createHash, X509Certificate } from "node:crypto";
      import { readFileSync } from "node:fs";
      import assert from "node:assert/strict";
      const mode = ${JSON.stringify(mode)};
      const cert = new X509Certificate(readFileSync(${JSON.stringify(certPath)}));
      if (mode === "spki") addBlockedSPKIForTesting(createHash("sha256").update(cert.publicKey.export({type:"spki",format:"der"})).digest());
      if (mode === "der") addBlockedCertificateForTesting(createHash("sha256").update(cert.raw).digest());
      const request = () => fetch(${JSON.stringify(h3Server.url.toString())}, {protocol:"http3", keepalive:false, tls:{rejectUnauthorized:true}});
      if (mode === "trusted") assert.equal(await (await request()).text(), "verified HTTP3 TLS");
      else await assert.rejects(request(), error => error.code === "HTTP3HandshakeFailed");
      console.log(JSON.stringify({http3:mode,pass:true}));
    `;
    child = Bun.spawn([process.execPath, "--eval", code], { env, stdout: "pipe", stderr: "pipe" });
    timer = setTimeout(() => child.kill(), 30_000);
    const [status, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    assert.equal(status, 0, `HTTP3 ${mode} child failed: ${stderr}`);
    assert.deepEqual(
      JSON.parse(
        stdout
          .trim()
          .split("\n")
          .find(line => line.startsWith('{"http3":')) || "null",
      ),
      { http3: mode, pass: true },
    );
  } finally {
    clearTimeout(timer);
    child?.kill();
    h3Server.stop(true);
    rmSync(directory, { recursive: true, force: true });
  }
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  tls: identity,
  http3: true,
  fetch() {
    return new Response("verified local TLS");
  },
});
const checks = [];
assert.equal(typeof addBlockedSPKIForTesting, "function");
assert.equal(typeof clearBlockedSPKIsForTesting, "function");
assert.equal(typeof addBlockedCertificateForTesting, "function");
assert.equal(typeof clearBlockedCertificatesForTesting, "function");
try {
  // TCP supports per-request CA; the 1.3.14 HTTP/3 backport instead loads
  // NODE_EXTRA_CA_CERTS at startup. Each H3 case runs a fresh asynchronous child
  // against an H3-only server, so neither TCP fallback nor session reuse can pass.
  await assert.rejects(fetch(server.url, { keepalive: false }));
  checks.push("http1: default rejects untrusted fixture");
  const response = await fetch(server.url, {
    keepalive: false,
    tls: { ca: identity.cert, rejectUnauthorized: true },
  });
  assert.equal(await response.text(), "verified local TLS");
  checks.push("http1: explicit CA succeeds");
  for (const mode of ["untrusted", "trusted", "spki", "der"]) {
    await checkHTTP3(mode);
    checks.push(`http3: ${mode} using startup extra-CA store`);
  }

  async function connect(ca) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port: server.port, ca, rejectUnauthorized: true });
      socket.once("error", reject);
      socket.once("secureConnect", () => {
        try {
          assert.equal(socket.authorized, true);
          resolve();
        } catch (error) {
          reject(error);
        } finally {
          socket.destroy();
        }
      });
    });
  }
  await assert.rejects(connect(undefined));
  await connect(identity.cert);
  checks.push("node:tls: default rejection and explicit CA success");
  // The hook adds only a public test-fixture key. The production denylist is
  // unaffected and remains covered separately by its exact-certificate tests.
  const spki = new X509Certificate(identity.cert).publicKey.export({ type: "spki", format: "der" });
  addBlockedSPKIForTesting(createHash("sha256").update(spki).digest());
  await assert.rejects(connect(identity.cert), error => error.code === "CERT_REVOKED");
  checks.push("node:tls: blocked explicit CA rejected with CERT_REVOKED");
  const report = await new Promise((resolve, reject) => {
    const socket = tls.connect({ host: "127.0.0.1", port: server.port, ca: identity.cert, rejectUnauthorized: false });
    socket.once("error", reject);
    socket.once("secureConnect", () => {
      resolve({ authorized: socket.authorized, error: socket.authorizationError });
      socket.destroy();
    });
  });
  assert.deepEqual(report, { authorized: false, error: "CERT_REVOKED" });
  checks.push("node:tls: insecure opt-out reports CERT_REVOKED, not authorized");
  // Use fresh ports to exclude previously authenticated connection/session reuse.
  for (const protocol of ["http1"]) {
    const blockedServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      tls: identity,
      http3: true,
      fetch: () => new Response("unexpected"),
    });
    try {
      await assert.rejects(
        fetch(blockedServer.url, {
          ...(protocol === "http3" ? { protocol: "http3" } : {}),
          tls: { ca: identity.cert, rejectUnauthorized: true },
          keepalive: false,
        }),
        error => error.code === (protocol === "http3" ? "HTTP3HandshakeFailed" : "CERT_REVOKED"),
      );
      checks.push(`${protocol}: blocked explicit CA rejected`);
    } finally {
      blockedServer.stop(true);
    }
  }
  // Mutual TLS: an insecure client can inspect the server certificate, but the
  // strict server must still refuse this independently blocked client identity.
  const mutual = tls.createServer({ ...identity, ca: identity.cert, requestCert: true, rejectUnauthorized: true });
  await new Promise((resolve, reject) => {
    mutual.once("error", reject);
    mutual.listen(0, "127.0.0.1", resolve);
  });
  let client;
  try {
    const seen = new Promise((resolve, reject) => {
      mutual.once("secureConnection", socket => {
        socket.destroy();
        reject(new Error("blocked mTLS client accepted"));
      });
      mutual.once("tlsClientError", (error, socket) => {
        // net.ts destroys the socket with this same error after tlsClientError.
        // Handle that expected duplicate without hiding any different failure.
        socket.on("error", socketError => {
          assert.equal(socketError.code, "CERT_REVOKED");
        });
        resolve(error.code);
      });
    });
    client = tls.connect({
      host: "127.0.0.1",
      port: mutual.address().port,
      ...identity,
      ca: identity.cert,
      rejectUnauthorized: false,
    });
    client.on("error", () => {}); // Server rejection can also surface here.
    assert.equal(await seen, "CERT_REVOKED");
    checks.push("mTLS: strict server rejects blocked client key");
  } finally {
    client?.destroy();
    mutual.close();
  }
  clearBlockedSPKIsForTesting();
  await connect(identity.cert);
  checks.push("cleared test list restores valid explicit CA connection");
  // Independently exercise the exact-DER branch, with no synthetic SPKI entry.
  const fixtureCert = new X509Certificate(identity.cert);
  assert.equal(certificateBlockedErrorForTesting(identity.cert), 0);
  addBlockedCertificateForTesting(createHash("sha256").update(fixtureCert.raw).digest());
  assert.equal(certificateBlockedErrorForTesting(identity.cert), 23);
  await assert.rejects(connect(identity.cert), error => error.code === "CERT_REVOKED");
  checks.push("node:tls: exact-DER blocked explicit CA rejected");
  for (const protocol of ["http1"]) {
    const blockedServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      tls: identity,
      http3: true,
      fetch: () => new Response("unexpected"),
    });
    try {
      await assert.rejects(
        fetch(blockedServer.url, {
          ...(protocol === "http3" ? { protocol: "http3" } : {}),
          tls: { ca: identity.cert, rejectUnauthorized: true },
          keepalive: false,
        }),
        error => error.code === (protocol === "http3" ? "HTTP3HandshakeFailed" : "CERT_REVOKED"),
      );
      checks.push(`${protocol}: exact-DER blocked explicit CA rejected`);
    } finally {
      blockedServer.stop(true);
    }
  }
  clearBlockedCertificatesForTesting();
  assert.equal(certificateBlockedErrorForTesting(identity.cert), 0);
  await connect(identity.cert);
  checks.push("cleared DER test list restores valid explicit CA connection");
  console.log(
    JSON.stringify({
      tls: "PASS",
      version: Bun.version,
      removedRootCount: removedRoots.size,
      realBlockedCertificateCount: manifest.length,
      checks,
      // Real public certificates exercise the production matcher; handshakes use
      // only synthetic identities. No real intermediate private keys are needed.
      scope: "bundled roots, 32 real certificate matches, normal TLS, synthetic SPKI and DER handshakes",
    }),
  );
} finally {
  clearBlockedCertificatesForTesting();
  clearBlockedSPKIsForTesting();
  server.stop(true);
}
