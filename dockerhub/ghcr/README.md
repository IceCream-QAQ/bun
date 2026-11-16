# Custom Bun 1.3.17 images

This is a **custom security-patched build based on Bun 1.3.14**, not the complete
upstream Bun 1.3.17 release. The runtime reports 1.3.17 as requested by the owner.
It retains Brotli 1.2.1 and backports the HTTP/3 QPACK decoded-header limits from
upstream PR #46392 (GHSA-cf8x-9m69-3gg3), adapted to the Zig runtime.

The TLS backport updates the bundled trust store to NSS 3.131.1 and adapts
upstream PR #46300 (GHSA-26q8-h657-pf84) to this older runtime. It rejects the
October eight compromised emSign ECDSA public keys by SPKI SHA-256, including
cross-signed certificates. Separately, it rejects the exact DER fingerprints of
eight RSA G2 intermediate certificates revoked on November 7 and their eight
AAA cross-signed certificates revoked on October 21. The RSA revocation reason
is cessationOfOperation, **not proven private-key compromise**; unrelated
certificates using a non-compromised key are not automatically key-blocked.
See `test/js/node/tls/fixtures/emsign` for public certificate evidence.

Both checks are applied to the constructed certificate chain independently of
the trust store. TCP TLS clients and server client-cert authentication cover
bundled/system/extra/explicit CA sources. This older HTTP/3 client uses its shared
default store (including NODE_EXTRA_CA_CERTS); it does not implement the per-fetch
tls.ca option, and this backport does not add that unrelated API feature. This is a bounded local distrust list, not
an automatic online CRL/OCSP service or a claim to cover every revoked certificate.
Applications explicitly disabling certificate verification remain insecure;
TCP TLS reports the revoked diagnostic rather than falsely authorizing the peer.

`publish-patched-ghcr.yml` is manually dispatched on `bun-1.3.14-brotli-security`.
Both libc builds check out the exact workflow commit (`github.sha`), never a
moving branch. GNU and musl source builds produce linux/amd64 baseline executables.
The upstream Debian, slim, Alpine and distroless runtime layouts are retained.

Publication writes only `1.3.17`, `1.3.17-slim`, `1.3.17-alpine`,
`1.3.17-distroless` and the matching `1.3` aliases. Existing `1.3.15` and `1.3.16` tags are not
changed and no `latest` tag is created. All images remain publicly pullable.

The GNU release build must first pass the complete four-file TLS/HTTP3 regression
suite (currently 148 tests plus 3 existing TODOs). Before publishing any variant,
all four images must pass version/revision,
architecture, executable identity and Brotli regression checks, plus HTTP/3
request size/count limits, response size limits, unrelated in-flight request
survival, POST/PATCH non-replay and recovery. TLS image checks verify removed
root fingerprints, default rejection of an untrusted test identity, explicit
CA success for TCP and extra-CA success for HTTP/3, synthetic blocked-key
rejection over TCP/HTTP/3 and mutual TLS,
and insecure-opt-out diagnostics. They use test-only hooks and public local
fixtures, never leaked CA keys or forged real-CA identities. The HTTP/3 check is loopback-only
inside a network-isolated, CPU/memory-limited container. The public TLS fixture
comes from the repository test harness, not from any deployment.

The workflow uses `contents: read` and grants `packages: write` only to its
publication job. Runtime results and tag/digest records are retained as artifacts.
