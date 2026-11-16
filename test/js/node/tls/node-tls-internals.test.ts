import {
  addBlockedSPKIForTesting,
  canonicalizeIP,
  clearBlockedSPKIsForTesting,
  addBlockedCertificateForTesting,
  clearBlockedCertificatesForTesting,
  certificateBlockedErrorForTesting,
} from "bun:internal-for-testing";
import { createTest } from "node-harness";
import { bunEnv, bunExe, tempDir } from "harness";
import { createHash, X509Certificate } from "node:crypto";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import {
  connect,
  createServer,
  getCACertificates,
  rootCertificates,
  type ConnectionOptions,
  type Server,
  type TlsOptions,
  type TLSSocket,
} from "tls";
const { afterEach, describe, expect } = createTest(import.meta.path);

describe("NodeTLS.cpp", () => {
  test("canonicalizeIP", () => {
    expect(canonicalizeIP("127.0.0.1")).toBe("127.0.0.1");
    expect(canonicalizeIP("10.1.0.1")).toBe("10.1.0.1");
    expect(canonicalizeIP("::1")).toBe("::1");
    expect(canonicalizeIP("fe80:0:0:0:0:0:0:1")).toBe("fe80::1");
    expect(canonicalizeIP("fe80:0:0:0:0:0:0:0")).toBe("fe80::");
    expect(canonicalizeIP("fe80::0000:0010:0001")).toBe("fe80::10:1");
    expect(canonicalizeIP("0001:2222:3333:4444:5555:6666:7777:0088")).toBe("1:2222:3333:4444:5555:6666:7777:88");

    expect(canonicalizeIP("0001:2222:3333:4444:5555:6666::")).toBe("1:2222:3333:4444:5555:6666::");

    expect(canonicalizeIP("a002:B12:00Ba:4444:5555:6666:0:0")).toBe("a002:b12:ba:4444:5555:6666::");

    // IPv4 address represented in IPv6
    expect(canonicalizeIP("0:0:0:0:0:ffff:c0a8:101")).toBe("::ffff:192.168.1.1");

    expect(canonicalizeIP("::ffff:192.168.1.1")).toBe("::ffff:192.168.1.1");
  });

  test("rootCertificates", () => {
    expect(rootCertificates).toBeInstanceOf(Array);
    expect(rootCertificates.length).toBeGreaterThan(0);
    expect(typeof rootCertificates[0]).toBe("string");

    for (const cert of rootCertificates) {
      expect(cert).toStartWith("-----BEGIN CERTIFICATE-----");
      expect(cert).toEndWith("-----END CERTIFICATE-----");
    }
  });
});

// Port of node's test/parallel/test-tls-spki-blocklist.js. The chain is agent6 -> ca3 (intermediate) -> ca1 (root), and
// agent6-cert.pem bundles ca3. ca1 signs agent1 directly. ca2 is unrelated to both.
describe("blocked public keys", () => {
  const readKey = (name: string) => readFileSync(join(import.meta.dir, "../test/fixtures/keys", name), "utf8");
  const spkiSha256 = (pem: string) =>
    createHash("sha256")
      .update(new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" }))
      .digest();

  const rootCert = readKey("ca1-cert.pem");
  const leafKey = readKey("agent6-key.pem");
  const leafChain = readKey("agent6-cert.pem");
  const unaffectedKey = readKey("agent1-key.pem");
  const unaffectedCert = readKey("agent1-cert.pem");
  const unrelatedCert = readKey("ca2-cert.pem");

  const intermediateSpkiHash = spkiSha256(readKey("ca3-cert.pem"));
  const leafSpkiHash = spkiSha256(leafChain);
  const unrelatedSpkiHash = spkiSha256(unrelatedCert);

  const servers: Server[] = [];
  // A TLS 1.3 client is done before the server has read its certificate, so clients stay open until the test is over.
  const clients: TLSSocket[] = [];
  afterEach(async () => {
    // The test lists are process-wide: retire all handshakes before mutating
    // them, including TLS 1.3 servers which finish after their clients.
    for (const client of clients.splice(0)) client.destroy();
    await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
    clearBlockedSPKIsForTesting();
    clearBlockedCertificatesForTesting();
  });

  async function listen(options: TlsOptions) {
    const server = createServer(options, socket => socket.resume());
    servers.push(server);
    await once(server.listen(0, "127.0.0.1"), "listening");
    return server;
  }

  const authorization = ({ authorized, authorizationError }: TLSSocket) => ({ authorized, authorizationError: authorizationError ?? null });

  /** What the client saw: the error that ended the handshake, or how the connection was authorized. */
  function connectTo(server: Server, options: ConnectionOptions) {
    const { promise, resolve } = Promise.withResolvers<object>();
    const client = connect({
      host: "127.0.0.1",
      port: (server.address() as AddressInfo).port,
      checkServerIdentity: () => undefined,
      ...options,
    });
    clients.push(client);
    client.once("error", err => resolve({ error: (err as NodeJS.ErrnoException).code }));
    client.once("secureConnect", () => resolve(authorization(client)));
    client.once("close", () => resolve({ closed: true }));
    return promise;
  }

  /** What the server saw of its next client: the same, from the other side. */
  function nextClientOf(server: Server, allowUnauthorized = false) {
    const { promise, resolve } = Promise.withResolvers<object>();
    let diagnostic: string | undefined;
    server.once("secureConnection", socket => {
      socket.on("error", () => {});
      resolve(allowUnauthorized ? { ...authorization(socket), diagnostic } : authorization(socket));
    });
    server.once("tlsClientError", (err, socket) => {
      // This baseline emits the diagnostic before deciding whether to allow the
      // connection, and may then emit the same error on the destroyed socket.
      socket.on("error", () => {});
      diagnostic = (err as NodeJS.ErrnoException).code;
      if (!allowUnauthorized) resolve({ error: diagnostic, ...authorization(socket) });
    });
    return promise;
  }

  test("exact-certificate rejection does not reject another certificate with the same public key", async () => {
    const original = readKey("ca3-cert.pem");
    // Reissued only from the repository's own ca1/ca3 test identities, with a new
    // serial. This is not an emSign key or a forged public-CA certificate.
    const reissued = readFileSync(join(import.meta.dir, "fixtures/ca3-reissued-blocklist-cert.pem"), "utf8");
    expect(spkiSha256(original)).toEqual(spkiSha256(reissued));
    expect(new X509Certificate(original).raw).not.toEqual(new X509Certificate(reissued).raw);
    expect(certificateBlockedErrorForTesting(original)).toBe(0);
    expect(certificateBlockedErrorForTesting(reissued)).toBe(0);
    addBlockedCertificateForTesting(createHash("sha256").update(new X509Certificate(original).raw).digest());
    expect(certificateBlockedErrorForTesting(original)).toBe(23);
    expect(certificateBlockedErrorForTesting(reissued)).toBe(0);
    expect(await connectTo(await listen({ key: leafKey, cert: leafChain }), { ca: rootCert })).toEqual({
      error: "CERT_REVOKED",
    });
    const leafOnly = leafChain.slice(
      0,
      leafChain.indexOf("-----END CERTIFICATE-----") + "-----END CERTIFICATE-----".length,
    );
    expect(await connectTo(await listen({ key: leafKey, cert: leafOnly + "\n" + reissued }), { ca: rootCert })).toEqual(
      { authorized: true, authorizationError: null },
    );
    clearBlockedCertificatesForTesting();
    expect(certificateBlockedErrorForTesting(original)).toBe(0);
    // Unlike certificate revocation, a compromised SPKI must reject both copies.
    addBlockedSPKIForTesting(spkiSha256(original));
    expect(certificateBlockedErrorForTesting(original)).toBe(23);
    expect(certificateBlockedErrorForTesting(reissued)).toBe(23);
  });

  describe("in the server's chain", () => {
    const server = () => listen({ key: leafKey, cert: leafChain });

    test("nothing blocked: the chain is accepted", async () => {
      expect(await connectTo(await server(), { ca: rootCert })).toEqual({ authorized: true, authorizationError: null });
    });

    test("a blocked intermediate is rejected", async () => {
      addBlockedSPKIForTesting(intermediateSpkiHash);
      expect(await connectTo(await server(), { ca: rootCert })).toEqual({ error: "CERT_REVOKED" });
    });

    test("a blocked leaf is rejected", async () => {
      addBlockedSPKIForTesting(leafSpkiHash);
      expect(await connectTo(await server(), { ca: rootCert })).toEqual({ error: "CERT_REVOKED" });
    });

    test("rejectUnauthorized: false reports CERT_REVOKED", async () => {
      addBlockedSPKIForTesting(intermediateSpkiHash);
      expect(await connectTo(await server(), { ca: rootCert, rejectUnauthorized: false })).toEqual({
        authorized: false,
        authorizationError: "CERT_REVOKED",
      });
    });

    test("a blocked key takes precedence over an untrusted root", async () => {
      expect(await connectTo(await server(), { ca: unrelatedCert })).toEqual({
        error: "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
      });
      addBlockedSPKIForTesting(intermediateSpkiHash);
      expect(await connectTo(await server(), { ca: unrelatedCert })).toEqual({ error: "CERT_REVOKED" });
    });

    test("clearing the list accepts the chain again", async () => {
      addBlockedSPKIForTesting(intermediateSpkiHash);
      clearBlockedSPKIsForTesting();
      expect(await connectTo(await server(), { ca: rootCert })).toEqual({ authorized: true, authorizationError: null });
    });

    test("the hook validates its argument", () => {
      // @ts-expect-error
      expect(() => addBlockedSPKIForTesting("not a buffer")).toThrow(
        expect.objectContaining({ code: "ERR_INVALID_ARG_TYPE" }),
      );
      expect(() => addBlockedSPKIForTesting(Buffer.alloc(31))).toThrow(
        expect.objectContaining({ code: "ERR_OUT_OF_RANGE" }),
      );
    });
  });

  describe("outside the verified chain", () => {
    const server = () => listen({ key: leafKey, cert: `${leafChain}\n${unrelatedCert}` });

    test("an unused certificate the peer sent is ignored when the chain verifies", async () => {
      addBlockedSPKIForTesting(unrelatedSpkiHash);
      expect(await connectTo(await server(), { ca: rootCert })).toEqual({ authorized: true, authorizationError: null });
    });

    test("every certificate the peer sent is checked when the chain does not verify", async () => {
      addBlockedSPKIForTesting(unrelatedSpkiHash);
      expect(await connectTo(await server(), { ca: unrelatedCert })).toEqual({ error: "CERT_REVOKED" });
    });
  });

  describe("in the client's chain", () => {
    const server = (rejectUnauthorized: boolean) =>
      listen({ key: unaffectedKey, cert: unaffectedCert, ca: rootCert, requestCert: true, rejectUnauthorized });
    const client = { key: leafKey, cert: leafChain, ca: rootCert };

    test("nothing blocked: the chain is accepted", async () => {
      const listening = await server(true);
      const seen = nextClientOf(listening);
      connectTo(listening, client);
      expect(await seen).toEqual({ authorized: true, authorizationError: null });
    });

    test("rejectUnauthorized: false reports CERT_REVOKED", async () => {
      addBlockedSPKIForTesting(intermediateSpkiHash);
      const listening = await server(false);
      const seen = nextClientOf(listening, true);
      connectTo(listening, client);
      expect(await seen).toEqual({ authorized: false, authorizationError: "CERT_REVOKED", diagnostic: "CERT_REVOKED" });
    });

    test("rejectUnauthorized: true rejects the client", async () => {
      addBlockedSPKIForTesting(intermediateSpkiHash);
      const listening = await server(true);
      const seen = nextClientOf(listening);
      connectTo(listening, client);
      expect(await seen).toEqual({ error: "CERT_REVOKED", authorized: false, authorizationError: "CERT_REVOKED" });
    });
  });

  // fetch() runs its handshakes on another thread than the one that fills the list.
  describe("fetch", () => {
    const serve = () =>
      Bun.serve({ port: 0, tls: { key: leafKey, cert: leafChain }, fetch: () => new Response("reached") });
    const get = (url: URL) =>
      fetch(url, { tls: { ca: rootCert, checkServerIdentity: () => undefined } }).then(
        res => res.text(),
        err => err.code,
      );

    test("nothing blocked: the chain is accepted", async () => {
      using server = serve();
      expect(await get(server.url)).toBe("reached");
    });

    test("a blocked intermediate is rejected", async () => {
      addBlockedSPKIForTesting(intermediateSpkiHash);
      using server = serve();
      expect(await get(server.url)).toBe("CERT_REVOKED");
    });
  });
});

test("bundled roots exclude the three distrusted emSign roots", () => {
  const distrusted = [
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f",
    "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3",
  ];
  const fingerprints = new Set(
    rootCertificates.map(pem => createHash("sha256").update(new X509Certificate(pem).raw).digest("hex")),
  );
  expect(fingerprints.size).toBeGreaterThan(100);
  expect(distrusted.filter(hash => fingerprints.has(hash))).toEqual([]);
});

test("blocked intermediate is rejected from extra and SSL_CERT_FILE trust stores", async () => {
  const readKey = (name: string) => readFileSync(join(import.meta.dir, "../test/fixtures/keys", name), "utf8");
  using dir = tempDir("tls-blocked-extra", { "ca.pem": readKey("ca1-cert.pem") });
  const server = createServer({ key: readKey("agent6-key.pem"), cert: readKey("agent6-cert.pem") }, socket =>
    socket.end(),
  );
  await once(server.listen(0, "127.0.0.1"), "listening");
  const hash = createHash("sha256")
    .update(new X509Certificate(readKey("ca3-cert.pem")).publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const script = `
    import { addBlockedSPKIForTesting } from "bun:internal-for-testing";
    import { connect } from "node:tls";
    if (process.env.BLOCK_KEY) addBlockedSPKIForTesting(Buffer.from(process.env.BLOCK_KEY, "hex"));
    const socket = connect({ host: "127.0.0.1", port: +process.env.TEST_PORT, checkServerIdentity: () => undefined });
    socket.setTimeout(5000, () => { console.error("timeout"); socket.destroy(); process.exitCode = 1; });
    socket.on("error", err => console.log(err.code));
    socket.on("secureConnect", () => { console.log(socket.authorized ? "authorized" : socket.authorizationError); socket.end(); });
  `;
  try {
    for (const source of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"]) {
      for (const blocked of [false, true]) {
        await using proc = Bun.spawn({
          cmd: [bunExe(), "-e", script],
          env: {
            ...bunEnv,
            NODE_EXTRA_CA_CERTS: "",
            SSL_CERT_FILE: "",
            [source]: join(String(dir), "ca.pem"),
            TEST_PORT: String((server.address() as AddressInfo).port),
            BLOCK_KEY: blocked ? hash : "",
          },
          stdout: "pipe",
          stderr: "pipe",
        });
        const [stdout, stderr, code] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
        expect(code).toBe(0);
        expect(stderr).toBe("");
        expect(stdout.trim()).toBe(blocked ? "CERT_REVOKED" : "authorized");
      }
    }
  } finally {
    server.close();
  }
}, 30_000);

// Parse NSS objects independently of the Perl generator. In particular, comment
// lines inside a trust object must not terminate it before SERVER_AUTH is read.
test("bundled DER certificate set exactly matches NSS server-auth trust", () => {
  const source = readFileSync(join(import.meta.dir, "../../../../packages/bun-usockets/certdata.txt"), "utf8");
  const objects = source.split(/(?=^CKA_CLASS CK_OBJECT_CLASS )/m);
  const octets = (object: string, attribute: string) => {
    const match = object.match(new RegExp(`^${attribute} MULTILINE_OCTAL\\n([\\s\\S]*?)^END$`, "m"));
    expect(match).not.toBeNull();
    return Buffer.from([...match![1].matchAll(/\\([0-7]{3})/g)].map(m => parseInt(m[1], 8)));
  };
  const trustedSHA1 = new Set(
    objects
      .filter(
        o =>
          o.startsWith("CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n") &&
          /^CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR$/m.test(o),
      )
      .map(o => octets(o, "CKA_CERT_SHA1_HASH").toString("hex")),
  );
  const expected = objects
    .filter(o => o.startsWith("CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n"))
    .map(o => octets(o, "CKA_VALUE"))
    .filter(der => trustedSHA1.has(createHash("sha1").update(der).digest("hex")))
    .map(der => createHash("sha256").update(der).digest("hex"));
  const actual = rootCertificates.map(pem => createHash("sha256").update(new X509Certificate(pem).raw).digest("hex"));
  expect(expected.length).toBeGreaterThan(100);
  expect(actual.toSorted()).toEqual(expected.toSorted());
}, 30_000);

test("real revoked public certificates match their pinned fingerprints and the compiled denylist", () => {
  const dir = join(import.meta.dir, "fixtures/emsign");
  const fixtures = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  expect(fixtures.length).toBe(32);
  const compromisedKeys = fixtures.filter((f: any) => f.policy === "SPKI SHA-256");
  const revokedCertificates = fixtures.filter((f: any) => f.policy === "certificate DER SHA-256");
  expect(compromisedKeys.length).toBe(16);
  expect(new Set(compromisedKeys.map((f: any) => f.spki_sha256)).size).toBe(8);
  expect(revokedCertificates.length).toBe(16);
  expect(new Set(revokedCertificates.map((f: any) => f.cert_sha256)).size).toBe(16);
  for (const fixture of fixtures) {
    const pem = readFileSync(join(dir, fixture.file), "utf8");
    const certificate = new X509Certificate(pem);
    expect(createHash("sha256").update(certificate.raw).digest("hex")).toBe(fixture.cert_sha256);
    expect(
      createHash("sha256")
        .update(certificate.publicKey.export({ type: "spki", format: "der" }))
        .digest("hex"),
    ).toBe(fixture.spki_sha256);
    expect(certificateBlockedErrorForTesting(pem)).toBe(fixture.expected_error);
  }
});

test("real October public certificate matches a compiled compromised-key entry", () => {
  const pem = readFileSync(join(import.meta.dir, "fixtures/blocked-public-key-cert.pem"), "utf8");
  const cert = new X509Certificate(pem);
  expect(
    createHash("sha256")
      .update(cert.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex"),
  ).toBe("49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f");
  expect(certificateBlockedErrorForTesting(pem)).toBe(23);
  expect(certificateBlockedErrorForTesting("not a certificate")).toBe(1);
});
