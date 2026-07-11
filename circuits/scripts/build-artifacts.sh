#!/usr/bin/env bash
# Build circuit artifacts: compiled constraint systems, proving keys, and
# the verifying keys pinned by on-chain zk_verifier instances.
#
# M1 (in progress): this will
#   1. compile each circuit (transfer, withdraw) with the arkworks toolchain
#   2. apply the published trusted-setup ceremony transcript
#   3. emit reproducible artifacts under circuits/artifacts/<circuit>/
#      (proving key, verifying key, layout manifest, checksums)
#
# Artifacts are reproducible: anyone can rerun this script against the
# committed sources + ceremony transcript and get byte-identical keys.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "attesta-circuits: artifact build"
echo
echo "  No circuits are implemented yet (M1 in progress)."
echo "  This script is the single entry point that will generate proving"
echo "  and verifying keys once the transfer/withdraw circuits land."
echo
echo "  Nothing was generated."
