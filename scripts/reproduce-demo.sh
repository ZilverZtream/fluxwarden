#!/usr/bin/env bash
set -u
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${FLUXWARDEN_NODE:-node}" "$script_dir/reproduce-demo.mjs" "$@"
