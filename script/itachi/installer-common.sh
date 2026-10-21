#!/usr/bin/env bash
# Only sourced from a complete hash-verified, private staging copy.
set -euo pipefail
origin=${EASYTIER_MANAGED_ORIGIN:-https://www.itachi.fans}
[[ "$origin" == https://www.itachi.fans ]] || { echo 'This distribution uses only https://www.itachi.fans' >&2; exit 2; }
case $(uname -s) in
 Linux) root=/opt/easytier-itachi; state=/var/lib/easytier-itachi; unit=/etc/systemd/system/easytier-itachi.service; platform=linux; lock=/opt/.easytier-itachi-operation.lock ;;
 Darwin) root='/Library/Application Support/EasyTierItachi'; state="$root/state"; unit=/Library/LaunchDaemons/fans.itachi.easytier.plist; platform=macos; lock='/Library/Application Support/.easytier-itachi-operation.lock' ;;
 *) exit 2 ;;
esac
fail(){ echo "$*" >&2; exit 1; }
owner_mode(){ if [[ "$platform" == linux ]]; then stat -c '%u %a' "$1"; else stat -f '%u %Lp' "$1"; fi; }
no_links(){ local p=$1; while [[ "$p" != / && -n "$p" ]]; do [[ ! -L "$p" ]] || fail "Symlink path refused: $p" || return; p=${p%/*}; [[ -n "$p" ]] || p=/; done; }
private_path(){ no_links "$1"; [[ $(owner_mode "$1") == '0 700' ]] || fail "Expected root-owned private directory: $1"; if [[ "$platform" == macos ]]; then [[ $(ls -lde "$1" | wc -l | tr -d ' ') == 1 ]] || fail 'Extended ACL on private directory refused'; fi; }
# Relay settings are explicit public metadata. Invitations are read only from
# protected files; no invitation contents enter argv, receipts or shell variables.
managed_mode=leaf
prepare_only=0
prepared_identity_digest=none
relay_args=()
relay_args_digest=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
relay_invitation_digest=$(printf '%064d' 0)
private_file(){ no_links "$1"; [[ -f "$1" && $(owner_mode "$1") == '0 600' ]] || fail 'Relay invitation must be a root-owned mode-0600 regular file'; if [[ "$platform" == macos ]]; then [[ $(ls -lde "$1" | wc -l | tr -d ' ') == 1 ]] || fail 'Invitation extended ACL refused'; fi; }
parse_install_options(){
 local region=unspecified invitation='' value
 local endpoint_pattern='^(tcp|udp|quic|ws|wss)://([0-9a-fA-F:.]+|\[[0-9a-fA-F:.]+\]):[1-9][0-9]{0,4}/?$'
 local listeners=() adverts=()
 managed_mode=leaf;prepare_only=0;relay_args=();relay_invitation_source='';relay_invitation_digest=$(printf '%064d' 0)
 while (( $# )); do
  case "$1" in
   --prepare) [[ $prepare_only == 0 ]] || fail 'Duplicate prepare option';prepare_only=1;shift ;;
   --relay) [[ "$managed_mode" == leaf ]] || fail 'Duplicate relay mode';managed_mode=relay;shift ;;
   --relay-listen|--relay-advertise|--relay-region|--relay-invitation-file)
    [[ $# -ge 2 && -n "$2" ]] || fail 'Missing relay option value';value=$2
    case "$1" in
     --relay-listen|--relay-advertise)
      [[ ${#value} -le 256 && "$value" =~ $endpoint_pattern ]] || fail 'Relay endpoints require literal IP addresses and explicit ports'
      if [[ "$1" == --relay-listen ]];then listeners+=("$value");else adverts+=("$value");fi ;;
     --relay-region) [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail 'Invalid relay region';region=$value ;;
     --relay-invitation-file) [[ -z "$invitation" && "$value" == /* ]] || fail 'Invitation path must be a single absolute private path';invitation=$value ;;
    esac;shift 2 ;;
   *) fail 'Unknown installer option' ;;
  esac
 done
 if [[ "$managed_mode" == leaf ]];then [[ $prepare_only == 0 ]] || fail '--prepare requires explicit --relay';[[ ${#listeners[@]} == 0 && ${#adverts[@]} == 0 && -z "$invitation" && "$region" == unspecified ]] || fail 'Relay options require explicit --relay';return;fi
 [[ ${#listeners[@]} -ge 1 && ${#listeners[@]} -le 8 && ${#adverts[@]} -ge 1 && ${#adverts[@]} -le 8 ]] || fail 'Relay mode needs 1-8 explicit listeners and advertisements'
 relay_args=(--managed-relay --managed-region "$region")
 for value in "${listeners[@]}";do relay_args+=(--managed-listen "$value");done
 for value in "${adverts[@]}";do relay_args+=(--managed-advertise "$value");done
 if [[ -n "$invitation" ]];then
  private_file "$invitation";[[ $(wc -c < "$invitation") -le 2048 && $(wc -l < "$invitation") -le 1 ]] || fail 'Invalid invitation size'
  LC_ALL=C awk 'NR!=1 || length($0)<16 || length($0)>1024 || $0~/[^A-Za-z0-9._-]/ {bad=1} END {exit(bad || NR!=1)}' "$invitation" || fail 'Invalid invitation encoding'
  relay_invitation_source=$invitation;relay_invitation_digest=$(hash_file "$invitation")
 fi
}
write_relay_args(){ if (( ${#relay_args[@]} ));then printf '%s\n' "${relay_args[@]}";fi; }
validate_relay_before_mutation(){
 [[ "$managed_mode" == relay ]] || return 0
 local scratch="$stage/.relay-validation-state" rc=0
 [[ ! -e "$scratch" && ! -L "$scratch" ]] || fail 'Unexpected validation state'
 chmod 700 "$stage/easytier-core"
 # Status is native, local-only validation. These scratch keys are never used
 # or uploaded; suppress their public identity and retain the real identity.
 "$stage/easytier-core" --managed-state "$scratch" --managed-status "${relay_args[@]}" >/dev/null || rc=$?
 local name;for name in identity.lock identity.json public-identity.json;do if [[ -f "$scratch/$name" && ! -L "$scratch/$name" ]];then rm -- "$scratch/$name";fi;done
 if [[ -d "$scratch" && ! -L "$scratch" ]];then rmdir "$scratch";fi
 [[ $rc == 0 ]] || fail 'Native relay validation failed before installation changes'
}
assert_absent_service(){
 [[ ! -e "$unit.d" && ! -L "$unit.d" ]] || fail 'Unowned service drop-in directory exists'
 [[ ! -e "$unit" && ! -L "$unit" ]] || fail 'An existing service definition is not an absent baseline'
 if loaded;then fail 'A loaded same-name service already exists';fi
}
assert_prepared_identity(){
 [[ "$prepared_identity_digest" == none ]] && return 0
 private_file "$state/identity.json"
 [[ $(hash_file "$state/identity.json") == "$prepared_identity_digest" ]] || fail 'Prepared device identity changed; refusing enrollment transition'
}
record_optional(){ if grep -q "^$1"$'\t' "$root/install-record.tsv";then record_get "$1" || fail 'Duplicate owned receipt field';else printf '%s\n' "$2";fi; }
record_get(){ awk -F '\t' -v key="$1" '$1==key { n++;value=$2 } END {if(n!=1)exit 1;print value}' "$root/install-record.tsv"; }
write_record(){ local status=$1 tmp="$root/.record.$$"; (umask 077; printf 'format\t1\nplatform\t%s\ncore_sha256\t%s\npackage_sha256\t%s\nservice_sha256\t%s\norigin\t%s\nbaseline\tabsent\nstatus\t%s\nmode\t%s\nrelay_args_sha256\t%s\nrelay_invitation_sha256\t%s\nprepared_identity_sha256\t%s\n' "$platform" "$digest" "$package_digest" "$definition_digest" "$origin" "$status" "$managed_mode" "$relay_args_digest" "$relay_invitation_digest" "$prepared_identity_digest" > "$tmp"); chmod 600 "$tmp"; mv -f "$tmp" "$root/install-record.tsv"; }
operation_lock(){ no_links "${lock%/*}"; [[ $(owner_mode "${lock%/*}") == '0 755' || $(owner_mode "${lock%/*}") == '0 775' ]] || fail 'Untrusted installation parent'; mkdir -m 700 "$lock" || fail 'Another installer operation or a stale lock exists; refusing'; lock_owned=1; }
release_lock(){ if [[ ${lock_owned:-0} == 1 ]]; then rmdir "$lock"; lock_owned=0; fi; }
loaded(){ if [[ "$platform" == linux ]]; then [[ $(systemctl show -p LoadState --value easytier-itachi.service 2>/dev/null) != not-found ]]; else launchctl print system/fans.itachi.easytier >/dev/null 2>&1; fi; }
validate_live(){
 [[ -f "$unit" && ! -L "$unit" && $(owner_mode "$unit") == '0 644' ]] || fail 'Owned service definition missing or unsafe'
 [[ $(hash_file "$unit") == "$definition_digest" ]] || fail 'Live service definition differs; refusing to touch it'
 cmp -s "$unit" "$root/service-definition" || fail 'Service definition receipt differs'
 if [[ "$platform" == linux ]]; then
  [[ $(systemctl show -p FragmentPath --value easytier-itachi.service) == "$unit" ]] || fail 'Service fragment changed'
  [[ -z $(systemctl show -p DropInPaths --value easytier-itachi.service) ]] || fail 'Service has unknown drop-ins'
  local pid; pid=$(systemctl show -p MainPID --value easytier-itachi.service)
  if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then [[ $(readlink "/proc/$pid/exe") == "$version/easytier-core" ]] || fail 'Running service executable differs'; fi
 else
  if loaded; then launchctl print system/fans.itachi.easytier | grep -Fq "program = $version/easytier-core" || fail 'Loaded daemon executable differs'; fi
 fi
}
load_record(){
 private_path "$root"; [[ -f "$root/install-record.tsv" && ! -L "$root/install-record.tsv" && $(owner_mode "$root/install-record.tsv") == '0 600' ]] || fail 'No protected installation record'
 [[ $(record_get format) == 1 && $(record_get platform) == "$platform" && $(record_get baseline) == absent && $(record_get origin) == "$origin" ]] || fail 'Unsupported installation record'
 digest=$(record_get core_sha256); package_digest=$(record_get package_sha256); definition_digest=$(record_get service_sha256)
 [[ "$digest" =~ ^[0-9a-f]{64}$ && "$package_digest" =~ ^[0-9a-f]{64}$ && "$definition_digest" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid owned hashes'
 version="$root/versions/$digest"; no_links "$version/easytier-core"
 status=$(record_get status); [[ "$status" == installed || "$status" == absent || "$status" == staged ]] || fail 'Unknown install state'
 managed_mode=$(record_optional mode leaf);relay_args_digest=$(record_optional relay_args_sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855);relay_invitation_digest=$(record_optional relay_invitation_sha256 "$(printf '%064d' 0)")
 prepared_identity_digest=$(record_optional prepared_identity_sha256 none)
 [[ "$prepared_identity_digest" == none || "$prepared_identity_digest" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid prepared identity receipt'
 if [[ "$status" == staged ]];then assert_prepared_identity;fi
 [[ "$managed_mode" == leaf || "$managed_mode" == relay ]] || fail 'Unknown owned role mode'
 [[ "$relay_args_digest" =~ ^[0-9a-f]{64}$ && "$relay_invitation_digest" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid owned relay receipt'
 if [[ "$managed_mode" == relay ]];then
  if [[ "$status" != staged || -e "$state/relay-arguments" ]];then private_file "$state/relay-arguments";[[ $(hash_file "$state/relay-arguments") == "$relay_args_digest" ]] || fail 'Owned relay argument configuration changed';fi
  if [[ "$relay_invitation_digest" != "$(printf '%064d' 0)" && ( "$status" != staged || -e "$state/relay-invitation" ) ]];then private_file "$state/relay-invitation";[[ $(hash_file "$state/relay-invitation") == "$relay_invitation_digest" ]] || fail 'Owned relay invitation changed';fi
 fi
 # Protected staged receipt is written before any child creation, so early
 # failure remains recognizable without deleting generated device identity.
 if [[ "$status" == staged ]]; then
  if [[ -e "$state" ]]; then private_path "$state"; fi
  if [[ -e "$root/versions" ]]; then private_path "$root/versions"; fi
  if [[ ! -e "$version" ]]; then return; fi
 fi
 private_path "$state"; private_path "$version"
 [[ $(hash_file "$version/easytier-core") == "$digest" && $(hash_file "$version/MANIFEST.json") == "$package_digest" ]] || fail 'Installed package identity mismatch'
 verify_package "$version"
 if [[ "$status" != staged ]]; then
  [[ -f "$root/service-definition" && ! -L "$root/service-definition" && $(owner_mode "$root/service-definition") == '0 600' && $(hash_file "$root/service-definition") == "$definition_digest" ]] || fail 'Unsafe service receipt'
 fi
}
remove_owned_service(){
 validate_live
 if [[ "$platform" == linux ]]; then
  systemctl stop easytier-itachi.service
  systemctl disable easytier-itachi.service
  [[ $(hash_file "$unit") == "$definition_digest" ]] || fail 'Definition changed during stop'
  rm -- "$unit"; systemctl daemon-reload
 else
  if loaded; then launchctl bootout system/fans.itachi.easytier; fi
  [[ $(hash_file "$unit") == "$definition_digest" ]] || fail 'Definition changed during stop'
  rm -- "$unit"
 fi
 write_record absent
}
transaction_cleanup(){
 local rc=$?; trap - EXIT
 if [[ $rc != 0 && ${created_service:-0} == 1 ]]; then
  # Never remove or stop a definition replaced concurrently by another operator.
  if [[ -f "$unit" && ! -L "$unit" && $(hash_file "$unit") == "$definition_digest" ]]; then
   if [[ "$platform" == linux ]]; then systemctl daemon-reload; fi
   if (validate_live); then
    if [[ "$platform" == linux ]]; then systemctl stop easytier-itachi.service || true; systemctl disable easytier-itachi.service || true; elif loaded; then launchctl bootout system/fans.itachi.easytier || true; fi
    if [[ $(hash_file "$unit") == "$definition_digest" ]]; then rm -- "$unit"; [[ "$platform" != linux ]] || systemctl daemon-reload; write_record absent; fi
   else echo 'Could not verify live definition; did not stop or remove it' >&2; fi
  else echo 'Concurrent service change detected; left untouched for operator recovery' >&2; fi
 fi
 release_lock || true
 cleanup_stage
 exit "$rc"
}
run_install(){
 parse_install_options "$@"
 validate_relay_before_mutation
 stage_files+=(.relay-arguments)
 (umask 077;write_relay_args > "$stage/.relay-arguments")
 relay_args_digest=$(hash_file "$stage/.relay-arguments")
 local incoming_mode=$managed_mode incoming_args=$relay_args_digest incoming_invitation=$relay_invitation_digest
 operation_lock; trap transaction_cleanup EXIT
 local incoming_digest incoming_package
 incoming_digest=$(hash_file "$stage/easytier-core");incoming_package=$(hash_file "$stage/MANIFEST.json")
 if [[ -e "$root" ]]; then
  load_record
  [[ "$managed_mode" == "$incoming_mode" && "$relay_args_digest" == "$incoming_args" ]] || fail 'Existing owned install has different relay mode/settings; reviewed migration required'
  if [[ "$relay_invitation_digest" != "$incoming_invitation" ]];then
   [[ "$managed_mode" == relay && "$status" == staged && "$relay_invitation_digest" == "$(printf '%064d' 0)" && "$incoming_invitation" != "$(printf '%064d' 0)" ]] || fail 'Existing owned invitation cannot be changed'
   assert_absent_service
   [[ "$prepared_identity_digest" != none ]] || fail 'Prepare the relay identity before attaching an invitation'
   assert_prepared_identity
   # Permit only the first attachment to an unstarted owned staging record.
   # Keep the old receipt until the protected copy has been hash-verified.
  fi
  [[ "$digest" == "$incoming_digest" && "$package_digest" == "$incoming_package" ]] || fail 'This safe installer supports fresh installation / exact same-package only; upgrades require a reviewed migration'
  if [[ "$status" == installed ]]; then validate_live; if [[ "$platform" == linux ]]; then systemctl is-active --quiet easytier-itachi.service; else loaded; fi; echo 'Exact owned package already installed; no changes made'; return; fi
 else
  no_links "$root"; no_links "$state"
  [[ ! -e "$state" ]] || fail 'Unowned state directory exists'
  mkdir -m 700 "$root"; if [[ "$platform" == macos ]]; then chmod -N "$root"; fi; private_path "$root"
  digest=$incoming_digest;package_digest=$incoming_package;version="$root/versions/$digest"
  prepared_identity_digest=none
  definition_digest=$(printf '%064d' 0);write_record staged
 fi
 assert_absent_service
 if [[ ! -e "$root/versions" ]]; then mkdir -m 700 "$root/versions"; fi
 if [[ ! -e "$state" ]]; then mkdir -m 700 "$state"; fi
 if [[ "$platform" == macos ]]; then chmod -N "$state" "$root/versions"; fi
 private_path "$state";private_path "$root/versions"
 if [[ "$managed_mode" == relay ]];then
  if [[ ! -e "$state/relay-arguments" ]];then (umask 077;set -o noclobber;cat "$stage/.relay-arguments" > "$state/relay-arguments");fi
  private_file "$state/relay-arguments";[[ $(hash_file "$state/relay-arguments") == "$relay_args_digest" ]] || fail 'Relay configuration copy mismatch'
  if [[ -n "$relay_invitation_source" ]];then
   if [[ ! -e "$state/relay-invitation" ]];then (umask 077;set -o noclobber;cat "$relay_invitation_source" > "$state/relay-invitation");fi
   private_file "$state/relay-invitation";[[ $(hash_file "$state/relay-invitation") == "$incoming_invitation" ]] || fail 'Relay invitation copy mismatch'
   relay_invitation_digest=$incoming_invitation
   write_record staged
  fi
 fi
 if [[ ! -e "$version" ]]; then
  local vstage="$root/versions/.stage.$$";mkdir -m 700 "$vstage"
  while IFS= read -r name; do cp "$stage/$name" "$vstage/$name"; chmod 600 "$vstage/$name"; done < "$stage/.file-list"
  chmod 700 "$vstage/easytier-core" "$vstage/easytier-cli" "$vstage/"*.sh
  verify_package "$vstage"; mv "$vstage" "$version"
 fi
 # Invitation path is deliberately not part of the public metadata digest.
 # Only this protected fixed path is added to native argv, never its contents.
 local runtime_relay_args=("${relay_args[@]}")
 if [[ "$relay_invitation_digest" != "$(printf '%064d' 0)" ]];then runtime_relay_args+=(--managed-relay-invitation-file "$state/relay-invitation");fi
 # Initialize identity before startup; never race the native identity lock.
 assert_prepared_identity
 "$version/easytier-core" --managed-state "$state" --managed-status "${runtime_relay_args[@]}"
 assert_prepared_identity
 if [[ "$managed_mode" == relay ]];then
  private_file "$state/identity.json";prepared_identity_digest=$(hash_file "$state/identity.json");write_record staged
 fi
 if [[ $prepare_only == 1 ]];then
  echo 'Relay identity prepared; no service definition created or loaded. Issue an identity-bound invitation, then rerun the same package/options with --relay-invitation-file.'
  return
 fi
 local service_args=(--daemon --managed-origin "$origin" --managed-state "$state" --rpc-portal 127.0.0.1:57212 "${runtime_relay_args[@]}")
 local serialized_args='' arg
 for arg in "${service_args[@]}";do serialized_args+="\"$arg\" ";done
 if [[ "$platform" == linux ]]; then
  cat > "$root/service-definition" <<SERVICE
[Unit]
Description=EasyTier Itachi managed native network
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart="$version/easytier-core" $serialized_args
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$state
[Install]
WantedBy=multi-user.target
SERVICE
  systemd-analyze verify "$root/service-definition" 2>/dev/null || { cp "$root/service-definition" "$root/check.service"; systemd-analyze verify "$root/check.service"; rm "$root/check.service"; }
 else
  cat > "$root/service-definition" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>fans.itachi.easytier</string><key>ProgramArguments</key><array><string>$version/easytier-core</string>$(for arg in "${service_args[@]}";do printf '<string>%s</string>' "$arg";done)</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>Umask</key><integer>63</integer></dict></plist>
PLIST
  plutil -lint "$root/service-definition"
 fi
 chmod 600 "$root/service-definition";definition_digest=$(hash_file "$root/service-definition")
 # noclobber creates a new regular file atomically; it will not replace a foreign path.
 (set -o noclobber; cat "$root/service-definition" > "$unit")
 created_service=1;chmod 644 "$unit";write_record installed
 if [[ "$platform" == linux ]]; then systemctl daemon-reload;validate_live;systemctl enable --now easytier-itachi.service;systemctl is-active --quiet easytier-itachi.service
 else launchctl bootstrap system "$unit";validate_live;loaded;fi
 created_service=0
 echo "Installed background/startup service. Pending approval at $origin."
 echo "Rollback/uninstall: sudo bash '$version/rollback.sh' (baseline: no service; identity retained)."
}
run_remove(){
 operation_lock;trap transaction_cleanup EXIT;load_record
 if [[ "$status" == absent || "$status" == staged ]]; then [[ ! -e "$unit" ]] || fail 'Unexpected service exists'; if loaded;then fail 'Unexpected loaded service exists';fi;echo 'Baseline already restored; identity retained';return;fi
 remove_owned_service
 echo 'Restored original baseline: no EasyTier Itachi service. Identity and verified package retained.'
}
