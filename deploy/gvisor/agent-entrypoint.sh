#!/bin/sh
set -eu

umask 077

# Keep CLI state out of the workspace. A harness may mount an ephemeral
# CODEX_HOME at this path, but credentials must never be baked into this image.
mkdir -p "${CODEX_HOME:?CODEX_HOME must be set}"

exec "$@"
