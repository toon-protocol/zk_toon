#!/usr/bin/env bash
# Regenerate zk-prover's `land` fixtures (cs003_*, w003_cs003.json, inputs.json) from o1js 3.1.0.
# Usage: ./regenerate.sh <output-dir>
set -euo pipefail
cd "$(dirname "$0")"
out=$(mkdir -p "${1:?output dir}" && cd "$1" && pwd)
# `npm ci` runs patch-package, which applies patches/o1js+3.1.0.patch (the SPIKE_DUMP dump).
npm ci
SPIKE_DUMP="$out" node prove-local.mjs
