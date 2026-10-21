#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} == 0 ]] || { echo 'Run with sudo' >&2; exit 2; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
hash_file(){ if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
verify_package(){
 local dir=$1 line name sum seen='' count=0 manifest_hashes expected_hashes
 [[ -f "$dir/SHA256SUMS" && ! -L "$dir/SHA256SUMS" && -f "$dir/MANIFEST.json" && ! -L "$dir/MANIFEST.json" ]] || { echo 'Missing package integrity metadata' >&2; return 1; }
 verified_names=(SHA256SUMS)
 while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^([0-9a-f]{64})'  '([A-Za-z0-9_.-]+)$ ]] || { echo 'Invalid SHA256SUMS line' >&2; return 1; }
  sum=${BASH_REMATCH[1]}; name=${BASH_REMATCH[2]}
  case "$name" in easytier-core|easytier-cli|install.sh|uninstall.sh|rollback.sh|installer-common.sh|LICENSE|README.txt|MANIFEST.json) ;; *) echo 'Unexpected package member' >&2; return 1;; esac
  case " $seen " in *" $name "*) echo 'Duplicate package member' >&2; return 1;; esac
  [[ -f "$dir/$name" && ! -L "$dir/$name" && $(hash_file "$dir/$name") == "$sum" ]] || { echo "Package integrity failure: $name" >&2; return 1; }
  seen="$seen $name"; verified_names+=("$name"); count=$((count+1))
 done < "$dir/SHA256SUMS"
 [[ $count == 9 ]] || { echo 'Incomplete package' >&2; return 1; }
 # The manifest itself was hash-checked above. Cross-check its declared file hashes and sizes.
 manifest_hashes=$(awk '
  /^    "[A-Za-z0-9_.-]+": \{$/ {n=$0;sub(/^    "/,"",n);sub(/": \{$/,"",n);next}
  /^      "sha256": "[0-9a-f]+",$/ {h=$0;sub(/^      "sha256": "/,"",h);sub(/",$/,"",h);if(length(h)!=64)exit 1;next}
  /^      "bytes": [0-9]+$/ {z=$0;sub(/^      "bytes": /,"",z);if(n==""||h=="")exit 1;print h "  " n; n="";h="";c++}
  END {if(c!=8||n!=""||h!="")exit 1}' "$dir/MANIFEST.json") || return 1
 expected_hashes=$(grep -v '  MANIFEST.json$' "$dir/SHA256SUMS" | LC_ALL=C sort)
 [[ $(printf '%s\n' "$manifest_hashes" | LC_ALL=C sort) == "$expected_hashes" ]] || { echo 'Manifest/checksum disagreement' >&2; return 1; }
 while IFS=' ' read -r name size; do [[ $(wc -c < "$dir/$name" | tr -d ' ') == "$size" ]] || { echo 'Manifest size mismatch' >&2; return 1; }; done < <(awk '/^    "[A-Za-z0-9_.-]+": \{$/ {n=$0;sub(/^    "/,"",n);sub(/": \{$/,"",n)} /^      "bytes": [0-9]+$/ {z=$0;sub(/^      "bytes": /,"",z);print n " " z}' "$dir/MANIFEST.json")
}
verify_package "$here"
case $(uname -s) in Linux) stage_parent=/opt ;; Darwin) stage_parent='/Library/Application Support' ;; *) exit 2;; esac
[[ -d "$stage_parent" && ! -L "$stage_parent" ]] || exit 2
if [[ $(uname -s) == Darwin ]]; then
 [[ $(stat -f '%u %Lp' "$stage_parent") == '0 755' && $(ls -lde "$stage_parent" | wc -l | tr -d ' ') == 1 ]] || { echo 'Untrusted staging parent' >&2; exit 1; }
else [[ $(stat -c '%u %a' "$stage_parent") == '0 755' ]] || { echo 'Untrusted staging parent' >&2; exit 1; }; fi
stage=$(mktemp -d "$stage_parent/.easytier-itachi-stage.XXXXXXXX")
chmod 700 "$stage"
cleanup_stage(){ local f; for f in "${stage_files[@]}"; do rm -f -- "$stage/$f"; done; rm -f -- "$stage/.file-list"; rmdir "$stage"; }
stage_files=("${verified_names[@]}")
trap cleanup_stage EXIT
for name in "${stage_files[@]}"; do cp "$here/$name" "$stage/$name"; chmod 600 "$stage/$name"; done
verify_package "$stage"
printf '%s\n' "${verified_names[@]}" > "$stage/.file-list"
source "$stage/installer-common.sh"
run_remove
