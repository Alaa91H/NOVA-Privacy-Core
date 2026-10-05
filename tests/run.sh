#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

printf '== shell syntax ==\n'
while IFS= read -r -d '' f; do
  printf '  %s\n' "$f"
  bash -n "$f"
done < <(find scripts tests -type f -name '*.sh' -print0; find src -type f -name 'privacyctl' -print0)

printf '== python tests ==\n'
python3 tests/test_repository.py

printf '== static security audit ==\n'
bash scripts/security-audit-static.sh

printf '\nAll repository tests passed.\n'
