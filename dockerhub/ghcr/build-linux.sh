#!/usr/bin/env bash
set -euo pipefail
libc="$1"
# Derive provenance from the pinned source checkout, not the workflow commit.
unset BUILDKITE_COMMIT GITHUB_SHA GIT_SHA
if [[ "$libc" == musl ]]; then
  apk add --no-cache bash build-base linux-headers clang21 llvm21 llvm21-dev lld21 cmake ninja rust cargo python3 perl go git curl unzip xz pkgconf libatomic
  export PATH="/usr/lib/llvm21/bin:$PATH"
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$PWD"
  target=x64-musl-baseline
else
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends ca-certificates curl gnupg lsb-release software-properties-common ninja-build cmake build-essential binutils python3 perl golang-go git unzip xz-utils pkg-config
  curl --fail --show-error --location https://apt.llvm.org/llvm.sh -o /tmp/llvm.sh
  sudo bash /tmp/llvm.sh 21
  sudo apt-get install -y --no-install-recommends llvm-21-dev lld-21
  export PATH="/usr/lib/llvm-21/bin:$PATH"
  rustup toolchain install nightly --profile minimal --component rust-src
  export RUSTUP_TOOLCHAIN=nightly
  target=x64-baseline
fi
mkdir -p /tmp/bun-bootstrap
curl --fail --show-error --location --retry 5 "https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-linux-$target.zip" -o /tmp/bun-bootstrap/bun.zip
unzip -q /tmp/bun-bootstrap/bun.zip -d /tmp/bun-bootstrap
export PATH="/tmp/bun-bootstrap/bun-linux-$target:$PATH"
export CMAKE_BUILD_PARALLEL_LEVEL=2 CARGO_BUILD_JOBS=2
bun scripts/build.ts --profile=release --baseline=on --canary=off --ci=off --lto=off -j2
file build/release/bun || true
build/release/bun --revision
