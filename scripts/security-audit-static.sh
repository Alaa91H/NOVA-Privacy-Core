#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0
bad() { printf 'FAIL  %s\n' "$*" >&2; fail=1; }
ok()  { printf 'PASS  %s\n' "$*"; }

tmp_secret="$(mktemp)"
tmp_pipe="$(mktemp)"
trap 'rm -f "$tmp_secret" "$tmp_pipe"' EXIT

# 1. Syntax / lint
while IFS= read -r -d '' file; do
  bash -n "$file" || bad "bash syntax: $file"
done < <(
  find scripts tests -type f -name '*.sh' -print0 2>/dev/null
  find src -type f -name 'privacyctl' -print0 2>/dev/null
)
[[ "$fail" -eq 0 ]] && ok "shell syntax"

if command -v shellcheck >/dev/null 2>&1; then
  mapfile -d '' shell_files < <(
    find scripts src tests -type f \
      \( -name '*.sh' -o -path '*/privacyctl' \) -print0 2>/dev/null || true
  )
  if [[ "${#shell_files[@]}" -gt 0 ]]; then
    shellcheck -x "${shell_files[@]}" || bad "ShellCheck"
  fi
  [[ "$fail" -eq 0 ]] && ok "ShellCheck"
else
  printf 'SKIP  ShellCheck not installed\n'
fi

if python3 -m py_compile scripts/*.py 2>/dev/null; then
  ok "Python compile"
else
  bad "Python compile"
fi

# 2. GitHub Actions supply-chain pins
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
done < <(
  grep -RhsE '^[[:space:]]*uses:[[:space:]]+' .github/workflows 2>/dev/null || true
)
if [[ "$actions_bad" -eq 0 ]]; then
  ok "GitHub Actions pinned by full commit SHA"
else
  fail=1
fi

# 3. Secret material must never be committed.
if git grep -nE --   '-----BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----|PresharedKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{20,}|PrivateKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{20,}'   -- ':!docs/*' ':!README.md' >"$tmp_secret" 2>/dev/null; then
  cat "$tmp_secret" >&2
  bad "potential committed private key/PSK"
else
  ok "no committed key material signatures"
fi

tracked_secret_paths="$(
  git ls-files |
    grep -E '(^|/)(peer-exports|secrets)/|\.(key|psk|p12|pfx|agekey)$|\.tar\.age$' ||
    true
)"
if [[ -n "$tracked_secret_paths" ]]; then
  printf '%s\n' "$tracked_secret_paths" >&2
  bad "generated/secret paths are tracked by Git"
else
  ok "no generated/secret paths are tracked"
fi

# 4. Reject unaudited pipe-to-shell installers.
if git grep -nE --   'curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh|wget[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh'   -- scripts src config >"$tmp_pipe" 2>/dev/null; then
  cat "$tmp_pipe" >&2
  bad "pipe-to-shell installer pattern"
else
  ok "no pipe-to-shell installers"
fi

# 5. DNS services must not bind publicly.
if grep -RInE   'bind_hosts:[[:space:]]*\[?0\.0\.0\.0|interface:[[:space:]]+0\.0\.0\.0'   config/adguard config/unbound 2>/dev/null; then
  bad "DNS wildcard bind"
else
  ok "DNS templates avoid public wildcard binds"
fi

# 6. SSH baseline.
ssh_cfg="config/ssh/90-nova-privacy.conf"
if grep -qx 'PermitRootLogin no' "$ssh_cfg" &&
   grep -qx 'PasswordAuthentication no' "$ssh_cfg" &&
   grep -qx 'AuthenticationMethods publickey' "$ssh_cfg"; then
  ok "SSH template is key-only and root-disabled"
else
  bad "SSH template does not enforce root-disabled public-key-only policy"
fi

# 7. Constrain the third-party Amnezia package origin.
awg_install="scripts/install-awg.sh"
if grep -Fq 'Pin: release o=LP-PPA-amnezia' "$awg_install" &&
   grep -Fq 'Pin-Priority: 1' "$awg_install" &&
   grep -Fq 'Package: amneziawg amneziawg-tools amneziawg-dkms' "$awg_install"; then
  ok "Amnezia PPA is constrained to its required package family"
else
  bad "Amnezia PPA scope/pinning is incomplete"
fi

# 8. Release provenance and target-OS gates.
release=".github/workflows/release.yml"
ci=".github/workflows/ci.yml"
debian_digest='debian:13.7-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a'
if grep -Fq "$debian_digest" "$ci" &&
   grep -Fq "$debian_digest" "$release" &&
   grep -Fq 'release tag must point exactly at current main' "$release" &&
   grep -Fq 'needs: validate' "$release"; then
  ok "CI/release are Debian-target and provenance gated"
else
  bad "CI/release target/provenance gate missing"
fi

# 9. Mandatory project artifacts.
required_files=(
  docs/THREAT_MODEL.md
  docs/ARCHITECTURE.md
  docs/CRYPTO_POLICY.md
  docs/DEPLOYMENT_READINESS.md
  config/nftables/nova.nft.in
  scripts/install.sh
  scripts/live-acceptance.sh
  src/privacyctl
)
for required in "${required_files[@]}"; do
  [[ -s "$required" ]] || bad "missing required file: $required"
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

printf '\nStatic security audit passed.\n'
