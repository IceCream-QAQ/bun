"""Reuse upstream runtime stages, substituting only the source-built executable."""
import pathlib
import shutil
import sys

root = pathlib.Path(__file__).resolve().parents[2]
variant, binary, destination = sys.argv[1:]
assert variant in {"debian", "debian-slim", "alpine", "distroless"}
source = root / "dockerhub" / variant
dest = pathlib.Path(destination)
dest.mkdir(parents=True, exist_ok=True)
text = (source / "Dockerfile").read_text()
# Keep the upstream runtime stage byte-for-byte, including entrypoint and users.
runtime = "FROM " + text.split("\nFROM ", 1)[1]
base = "alpine:3.22" if variant == "alpine" else "debian:trixie-slim"
(dest / "Dockerfile").write_text(
    f"FROM {base} AS build\nCOPY --chmod=755 bun /usr/local/bin/bun\n\n" + runtime
)
shutil.copyfile(binary, dest / "bun")
entrypoint = source / "docker-entrypoint.sh"
if entrypoint.exists():
    shutil.copy2(entrypoint, dest / entrypoint.name)
assert "releases/download" not in (dest / "Dockerfile").read_text()
