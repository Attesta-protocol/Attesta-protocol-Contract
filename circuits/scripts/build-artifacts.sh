#!/usr/bin/env bash
# Build circuit artifacts: proving keys, the verifying keys pinned by
# on-chain zk_verifier instances, layout manifests, checksums, and the
# generated Poseidon constants for the contract layer.
#
# Artifacts are reproducible: this runs the setup from a fixed public
# seed (DEVELOPMENT KEYS — see artifacts/README.md), so anyone rerunning
# it against the committed sources gets byte-identical output. The
# production setup replaces the seeded RNG with the multi-party ceremony
# transcript (circuits/ceremony/); everything downstream is identical.
set -euo pipefail

cd "$(dirname "$0")/.."

cargo run --release --bin build-artifacts
