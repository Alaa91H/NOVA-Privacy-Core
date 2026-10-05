#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
require_root
load_runtime

for cmd in curl gpg sha256sum; do
  require_cmd "$cmd"
done

export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=600 update
apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends   ca-certificates curl gnupg

install -d -m 0755 /etc/apt/keyrings /etc/apt/sources.list.d /etc/apt/preferences.d
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl --proto '=https' --tlsv1.2 -fsSL   --connect-timeout 10 --max-time 30   https://cli.github.com/packages/githubcli-archive-keyring.gpg   -o "$tmp"

actual="$(sha256sum "$tmp" | awk '{print $1}')"
[[ "$actual" == "$NOVA_GITHUB_CLI_KEYRING_SHA256" ]] ||
  die "GitHub CLI keyring SHA-256 mismatch"

IFS=',' read -r -a allowed_fprs <<<"$NOVA_GITHUB_CLI_KEY_FPRS"
mapfile -t found_fprs < <(
  gpg --batch --show-keys --with-colons "$tmp" 2>/dev/null |
    awk -F: '$1=="fpr"{print toupper($10)}'
)
[[ "${#found_fprs[@]}" -ge 1 ]] || die "GitHub CLI keyring has no fingerprints"

trusted=0
for found in "${found_fprs[@]}"; do
  for allowed in "${allowed_fprs[@]}"; do
    if [[ "$found" == "${allowed^^}" ]]; then
      trusted=1
    fi
  done
done
[[ "$trusted" -eq 1 ]] || die "GitHub CLI keyring fingerprint is not in NOVA trust set"

install -m 0644 "$tmp" /etc/apt/keyrings/githubcli-archive-keyring.gpg

arch="$(dpkg --print-architecture)"
cat >/etc/apt/sources.list.d/github-cli.list <<EOF
deb [arch=$arch signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main
EOF

# The GitHub repository may provide only GitHub CLI; nevertheless keep an
# explicit package boundary so no third-party origin can override Ubuntu base
# packages if repository contents ever expand.
cat >/etc/apt/preferences.d/nova-github-cli <<'EOF'
Package: *
Pin: origin cli.github.com
Pin-Priority: 1

Package: gh
Pin: origin cli.github.com
Pin-Priority: 700
EOF

apt-get -o DPkg::Lock::Timeout=600 update
candidate="$(apt-cache policy gh | awk '/Candidate:/{print $2; exit}')"
[[ -n "$candidate" && "$candidate" != "(none)" ]] ||
  die "official GitHub CLI repository has no gh candidate"

apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends gh

gh_attestation_help="$(gh attestation verify --help 2>&1 || true)"
grep -q -- '--bundle' <<<"$gh_attestation_help" ||
  die "installed GitHub CLI does not support local attestation bundles"

installed="$(dpkg-query -W -f='${Version}' gh 2>/dev/null || echo unknown)"
write_runtime_kv NOVA_GITHUB_CLI_VERSION "$installed"
log "official GitHub CLI installed and attestation support verified: $installed"
