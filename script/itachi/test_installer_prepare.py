#!/usr/bin/env python3
"""Root-only isolated installer lifecycle tests; OS service commands are mocked."""
import hashlib,json,os,pathlib,subprocess,tempfile,unittest
SOURCE=pathlib.Path(__file__).resolve().with_name('installer-common.sh')
RUNTIME=pathlib.Path(os.environ.get("EASYTIER_TEST_RUNTIME",tempfile.gettempdir()))
BASE=['--relay','--relay-listen','tcp://0.0.0.0:57220','--relay-advertise','tcp://1.1.1.1:57220','--relay-region','fixture']
CORE='''#!/usr/bin/env bash
set -euo pipefail
s=''
while (( $# ));do if [[ $1 == --managed-state ]];then s=$2;shift 2;else shift;fi;done
mkdir -p "$s";chmod 700 "$s"
if [[ ! -f "$s/identity.json" ]];then (umask 077;printf '{"device_id":"fixture-uuid","private_key":"fixture-private-never-output"}' > "$s/identity.json");fi
printf '{"device_id":"fixture-uuid","device_public_key":"fixture-public"}\\n'
'''
ADAPTERS=r'''
root=$1/owned;state=$1/state;unit=$1/service;stage=$1/stage;lock=$1/lock
platform=linux;stage_files=()
shift
hash_file(){ sha256sum "$1" | cut -d' ' -f1; }
verify_package(){ [[ -f "$1/easytier-core" && -f "$1/MANIFEST.json" ]]; }
cleanup_stage(){ :; }
operation_lock(){ mkdir -m 700 "$lock";lock_owned=1; }
loaded(){ [[ -f "${unit}.loaded" ]]; }
systemd-analyze(){ :; }
systemctl(){
 printf '%s\n' "$*" >> "${unit}.calls"
 case "$1" in
 show) case "$3" in FragmentPath) printf '%s\n' "$unit";; DropInPaths) echo;; MainPID) echo 0;; esac;;
 enable) : > "${unit}.loaded";;
 disable|stop) rm -f "${unit}.loaded";;
 esac
}
run_install "$@"
'''
class PrepareTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='prepare-fixture-',dir=RUNTIME);self.p=pathlib.Path(self.tmp.name)
  st=self.p/'stage';st.mkdir(mode=0o700)
  for name,data in [('easytier-core',CORE),('easytier-cli','fixture'),('MANIFEST.json','fixture-manifest'),('install.sh','fixture-shell')]:
   (st/name).write_text(data);(st/name).chmod(0o700 if name=='easytier-core' else 0o600)
  (st/'.file-list').write_text('easytier-core\neasytier-cli\nMANIFEST.json\ninstall.sh\n')
  self.script=self.p/'runner.sh';self.script.write_text(SOURCE.read_text()+ADAPTERS)
  self.ticket=self.p/'ticket';self.ticket.write_text('fixture-invitation-never-output\n');self.ticket.chmod(0o600)
 def tearDown(self):self.tmp.cleanup()
 def run_install(self,*args,ok=True):
  r=subprocess.run(['bash',str(self.script),str(self.p),*args],text=True,capture_output=True)
  if ok:self.assertEqual(r.returncode,0,r.stderr+r.stdout)
  else:self.assertNotEqual(r.returncode,0,r.stdout)
  self.assertNotIn('fixture-private-never-output',r.stdout+r.stderr);self.assertNotIn('fixture-invitation-never-output',r.stdout+r.stderr)
  return r
 def record(self):return dict(line.split('\t',1) for line in (self.p/'owned/install-record.tsv').read_text().splitlines())
 def prepare(self):return self.run_install(*BASE,'--prepare')
 def test_prepare_public_identity_no_service(self):
  r=self.prepare();rec=self.record();self.assertEqual(rec['status'],'staged');self.assertEqual(rec['prepared_identity_sha256'],hashlib.sha256((self.p/'state/identity.json').read_bytes()).hexdigest());self.assertFalse((self.p/'service').exists());self.assertFalse((self.p/'service.calls').exists());self.assertIn('fixture-public',r.stdout)
 def test_prepare_repeat_preserves_identity_and_digest(self):
  self.prepare();before=(self.p/'state/identity.json').read_bytes();rec=self.record();self.prepare();self.assertEqual(rec,self.record());self.assertEqual(before,(self.p/'state/identity.json').read_bytes())
 def test_attach_ticket_install_then_exact_idempotent(self):
  self.prepare();before=(self.p/'state/identity.json').read_bytes();args_digest=self.record()['relay_args_sha256'];self.run_install(*BASE,'--relay-invitation-file',str(self.ticket));self.assertEqual(self.record()['status'],'installed');self.assertEqual(args_digest,self.record()['relay_args_sha256']);self.assertEqual(before,(self.p/'state/identity.json').read_bytes());self.assertEqual((self.p/'state/relay-invitation').read_bytes(),self.ticket.read_bytes());definition=(self.p/'service').read_bytes();r=self.run_install(*BASE,'--relay-invitation-file',str(self.ticket));self.assertIn('no changes made',r.stdout);self.assertEqual(definition,(self.p/'service').read_bytes());self.assertNotIn(self.ticket.read_text().strip(),definition.decode());self.assertIn('--managed-relay-invitation-file',definition.decode())
 def test_prepare_with_ticket_stays_staged(self):
  self.prepare();self.run_install(*BASE,'--prepare','--relay-invitation-file',str(self.ticket));self.assertEqual(self.record()['status'],'staged');self.assertFalse((self.p/'service').exists())
 def test_retry_after_copy_before_receipt(self):
  self.prepare();(self.p/'state/relay-invitation').write_bytes(self.ticket.read_bytes());(self.p/'state/relay-invitation').chmod(0o600);self.run_install(*BASE,'--relay-invitation-file',str(self.ticket));self.assertEqual(self.record()['status'],'installed')
 def test_installed_no_ticket_cannot_attach(self):
  self.run_install(*BASE);before=(self.p/'service').read_bytes();self.run_install(*BASE,'--relay-invitation-file',str(self.ticket),ok=False);self.assertEqual(before,(self.p/'service').read_bytes());self.assertFalse((self.p/'state/relay-invitation').exists())
 def test_ticket_change_denied(self):
  self.prepare();self.run_install(*BASE,'--prepare','--relay-invitation-file',str(self.ticket));rec=self.record();self.ticket.write_text('different-fixture-invitation\n');self.run_install(*BASE,'--relay-invitation-file',str(self.ticket),ok=False);self.assertEqual(rec,self.record())
 def test_existing_unit_and_loaded_guard_before_attach(self):
  self.prepare();(self.p/'service.loaded').touch();self.run_install(*BASE,'--relay-invitation-file',str(self.ticket),ok=False);self.assertFalse((self.p/'state/relay-invitation').exists());(self.p/'service.loaded').unlink();(self.p/'service').write_text('foreign');self.run_install(*BASE,'--relay-invitation-file',str(self.ticket),ok=False);self.assertFalse((self.p/'state/relay-invitation').exists())
 def test_changed_identity_denied(self):
  self.prepare();(self.p/'state/identity.json').write_text('different identity');self.run_install(*BASE,'--relay-invitation-file',str(self.ticket),ok=False);self.assertFalse((self.p/'service').exists());self.assertFalse((self.p/'state/relay-invitation').exists())
 def test_prepare_leaf_and_unknown_modes_denied(self):
  self.run_install('--prepare',ok=False);self.run_install(*BASE,'--unknown',ok=False);self.assertFalse((self.p/'owned').exists())
 def test_changed_public_args_and_package_denied(self):
  self.prepare();changed=BASE.copy();changed[4]='tcp://8.8.8.8:57220';self.run_install(*changed,'--relay-invitation-file',str(self.ticket),ok=False);(self.p/'stage/MANIFEST.json').write_text('changed');self.run_install(*BASE,'--relay-invitation-file',str(self.ticket),ok=False);self.assertFalse((self.p/'state/relay-invitation').exists())
 def test_unowned_state_not_adopted(self):
  (self.p/'state').mkdir(mode=0o700);self.run_install(*BASE,'--prepare',ok=False);self.assertFalse((self.p/'owned').exists())
if __name__=='__main__':unittest.main(verbosity=2)
