# Custom Bun 1.3.16 images

This is a **custom security-patched build based on Bun 1.3.14**, not the complete
upstream Bun 1.3.16 release. The runtime reports 1.3.16 as requested by the owner.
It retains Brotli 1.2.1 and backports the HTTP/3 QPACK decoded-header limits from
upstream PR #46392 (GHSA-cf8x-9m69-3gg3), adapted to the Zig runtime.

`publish-patched-ghcr.yml` is manually dispatched on `bun-1.3.14-brotli-security`.
Both libc builds check out the exact workflow commit (`github.sha`), never a
moving branch. GNU and musl source builds produce linux/amd64 baseline executables.
The upstream Debian, slim, Alpine and distroless runtime layouts are retained.

Publication writes only `1.3.16`, `1.3.16-slim`, `1.3.16-alpine`,
`1.3.16-distroless` and the matching `1.3` aliases. Existing `1.3.15` tags are not
changed and no `latest` tag is created. All images remain publicly pullable.

Before publishing any variant, all four images must pass version/revision,
architecture, executable identity and Brotli regression checks, plus HTTP/3
request size/count limits, response size limits, unrelated in-flight request
survival, POST/PATCH non-replay and recovery. The HTTP/3 check is loopback-only
inside a network-isolated, CPU/memory-limited container. The public TLS fixture
comes from the repository test harness, not from any deployment.

The workflow uses `contents: read` and grants `packages: write` only to its
publication job. Runtime results and tag/digest records are retained as artifacts.
