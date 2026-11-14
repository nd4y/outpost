#!/usr/bin/env bash
# The standard's scanner version/checksum stay authoritative. CI uses the
# official release asset API because the browser download route can fail alone.
set -euo pipefail

archive=""
output=".standards/bin/gitleaks"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive|--output)
      [[ $# -ge 2 ]] || exit 2
      if [[ "$1" == --archive ]]; then archive="$2"; else output="$2"; fi
      shift 2 ;;
    *) exit 2 ;;
  esac
done
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo 'Unsupported CI scanner platform' >&2; exit 1; }
expected='551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
grep -F 'gitleaks_8.30.1_linux_x64.tar.gz' .standards/install-gitleaks.mjs >/dev/null
grep -F "$expected" .standards/install-gitleaks.mjs >/dev/null
[[ ! -e "$output" && ! -L "$output" ]] || { echo 'Scanner output already exists' >&2; exit 1; }
temporary="$(mktemp -d "${TMPDIR:-/tmp}/outpost-scanner.XXXXXX")"
trap 'rm -f -- "$temporary/archive.tar.gz" "$temporary/gitleaks"; rmdir -- "$temporary"' EXIT
if [[ -n "$archive" ]]; then
  [[ -f "$archive" && ! -L "$archive" ]] || exit 1
  cp -- "$archive" "$temporary/archive.tar.gz"
else
  timeout 45s gh api repos/gitleaks/gitleaks/releases/assets/378332058 \
    --header 'Accept: application/octet-stream' > "$temporary/archive.tar.gz"
fi
[[ "$(stat -c %s "$temporary/archive.tar.gz")" == 8230402 ]] || { echo 'Scanner archive length mismatch' >&2; exit 1; }
printf '%s  %s\n' "$expected" "$temporary/archive.tar.gz" | sha256sum --check --status
# Extract just the pinned member after authenticating the entire archive.
tar -xzf "$temporary/archive.tar.gz" -C "$temporary" -- gitleaks
[[ -f "$temporary/gitleaks" && ! -L "$temporary/gitleaks" ]] || exit 1
chmod 0755 "$temporary/gitleaks"
[[ "$("$temporary/gitleaks" version)" == 8.30.1 ]] || { echo 'Scanner version mismatch' >&2; exit 1; }
mkdir -p -- "$(dirname -- "$output")"
# Hardlink creation is exclusive; a concurrent installer cannot replace output.
# The final file can be on another filesystem, so copy to a sibling first.
candidate="$(mktemp "$(dirname -- "$output")/.outpost-scanner.XXXXXX")"
trap 'rm -f -- "$temporary/archive.tar.gz" "$temporary/gitleaks" "$candidate"; rmdir -- "$temporary"' EXIT
cp -- "$temporary/gitleaks" "$candidate"
chmod 0755 "$candidate"
ln -- "$candidate" "$output"
printf 'Pinned Gitleaks 8.30.1 installed from verified official release archive\n'
