#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0
bad() { printf 'FAIL  %s\n' "$*" >&2; fail=1; }
ok() { printf 'PASS  %s\n' "$*"; }

# Syntax-check all maintained shell entry points.
while IFS= read -r -d '' f; do
  bash -n "$f" || bad "bash syntax: $f"
done < <(find scripts tests -type f -name '*.sh' -print0 2>/dev/null; find src -type f -name 'privacyctl' -print0 2>/dev/null)
[[ "$fail" -eq 0 ]] && ok "shell syntax"

if command -v shellcheck >/dev/null 2>&1; then
  mapfile -d '' shell_files < <(find scripts src tests -type f \( -name '*.sh' -o -path '*/privacyctl' \) -print0 2>/dev/null || true)
  if [[ "${#shell_files[@]}" -gt 0 ]]; then
    shellcheck -x "${shell_files[@]}" || bad "ShellCheck"
  fi
  [[ "$fail" -eq 0 ]] && ok "ShellCheck"
else
  printf 'SKIP  ShellCheck not installed\n'
fi

python3 -m py_compile scripts/*.py 2>/dev/null || bad "Python compile"
[[ "$fail" -eq 0 ]] && ok "Python compile"


# GitHub Actions are executable dependencies.  Require immutable commit SHAs,
# not floating tags such as @v4 or @main.
actions_bad=0
while IFS= read -r line; do
  use="${line#*uses: }"
  use="${use%%#*}"
  use="${use//[[:space:]]/}"
  [[ "$use" == ./* ]] && continue
  ref="${use##*@}"
  if [[ ! "$ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
    printf 'FAIL  unpinned GitHub Action: %s\n' "$use" >&2
    actions_bad=1
  fi
done < <(grep -RhsE '^[[:space:]]*uses:[[:space:]]+' .github/workflows 2>/dev/null || true)
if [[ "$actions_bad" -eq 0 ]]; then
  ok "GitHub Actions pinned by full commit SHA"
else
  fail=1
fi

# Secrets and dangerous installer patterns.
if git grep -nE -- '-----BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----|PresharedKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{20,}|PrivateKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{20,}' -- ':!docs/*' ':!README.md' >/tmp/nova-secret-scan.$$ 2>/dev/null; then
  cat /tmp/nova-secret-scan.$$ >&2
  bad "potential committed private key/PSK"
else
  ok "no committed key material signatures"
fi
rm -f /tmp/nova-secret-scan.$$

tracked_secret_paths="$(
  git ls-files |
    grep -E '(^|/)(peer-exports|secrets)/|\.(key|psk|p12|pfx|agekey)$|\.tar\.age
  cat /tmp/nova-pipe-scan.$$ >&2
  bad "pipe-to-shell installer pattern"
else
  ok "no pipe-to-shell installers"
fi
rm -f /tmp/nova-pipe-scan.$$

if grep -RInE 'bind_hosts:[[:space:]]*\[?0\.0\.0\.0|interface:[[:space:]]+0\.0\.0\.0' config/adguard config/unbound 2>/dev/null; then
  bad "DNS wildcard bind"
else
  ok "DNS templates avoid public wildcard binds"
fi

for required in   docs/THREAT_MODEL.md docs/ARCHITECTURE.md docs/CRYPTO_POLICY.md   config/nftables/nova.nft.in scripts/install.sh src/privacyctl; do
  [[ -s "$required" ]] || bad "missing required file: $required"
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
printf '\nStatic security audit passed.\n'
 ||
    true
)"
if [[ -n "$tracked_secret_paths" ]]; then
  printf '%s\n' "$tracked_secret_paths" >&2
  bad "generated/secret paths are tracked by Git"
else
  ok "no generated/secret paths are tracked"
fi

if git grep -nE -- 'curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh|wget[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh' -- scripts src config >/tmp/nova-pipe-scan.$ 2>/dev/null; then
  cat /tmp/nova-pipe-scan.$$ >&2
  bad "pipe-to-shell installer pattern"
else
  ok "no pipe-to-shell installers"
fi
rm -f /tmp/nova-pipe-scan.$$

if grep -RInE 'bind_hosts:[[:space:]]*\[?0\.0\.0\.0|interface:[[:space:]]+0\.0\.0\.0' config/adguard config/unbound 2>/dev/null; then
  bad "DNS wildcard bind"
else
  ok "DNS templates avoid public wildcard binds"
fi

for required in   docs/THREAT_MODEL.md docs/ARCHITECTURE.md docs/CRYPTO_POLICY.md   config/nftables/nova.nft.in scripts/install.sh src/privacyctl; do
  [[ -s "$required" ]] || bad "missing required file: $required"
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
printf '\nStatic security audit passed.\n'
