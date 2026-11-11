# Patched Bun GHCR images

The manually dispatched `publish-patched-ghcr.yml` workflow builds Linux amd64
executables from commit `59c898dd474149cbaa09274abea3b0d4a2d33e39`.
The source version is **Bun 1.3.14**, with Brotli 1.2.1 and the invalid block-switch
fix. The user-selected `1.3.15` and `1.3` distribution tags do **not** claim this
is upstream Bun 1.3.15. Runtime version and OCI labels preserve the actual version.

Published tags under `ghcr.io/icecream-qaq/bun`:

- `1.3.15`, `1.3`: Debian
- `1.3.15-slim`, `1.3-slim`: Debian slim
- `1.3.15-alpine`, `1.3-alpine`: Alpine/musl
- `1.3.15-distroless`, `1.3-distroless`: Distroless

No `latest`, major-only, or unrelated tags are updated. Each `1.3` alias is
checked against its corresponding `1.3.15` digest after publication.

The workflow compiles GNU and native musl executables separately with the
repository's release profile, baseline CPU target, and LTO disabled. Official
Bun is used only to bootstrap the build scripts; it is never packaged. The
build uses the repository's normal pinned dependency archives and prebuilt
WebKit library. It does not rebuild WebKit from source.

`prepare-context.py` preserves each upstream Dockerfile's runtime stage and
entrypoint, replacing only the download stage with the compiled executable.
All four images must pass the invalid Brotli block-switch checks (sync, async,
byte-wise stream, DecompressionStream, fetch), valid decompression, exact source
revision, Linux/x64 architecture, and byte-for-byte executable checks before
any image is published. Distroless tests invoke Bun directly and need no shell.

The workflow needs only `contents: read`; its publication job additionally
requests `packages: write`. Image visibility is managed separately in GitHub.
Workflow artifacts retain runtime checks and tag/digest records.
