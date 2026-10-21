#!/usr/bin/env python3
"""Nonprivileged package-integrity regression tests; never starts/stops a service."""
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent


class IntegrityTests(unittest.TestCase):
    def fixture(self, root):
        files = {'easytier-core': b'not executed', 'easytier-cli': b'not executed',
                 'LICENSE': b'fixture', 'README.txt': b'fixture'}
        for name in ['install.sh', 'uninstall.sh', 'rollback.sh', 'installer-common.sh']:
            files[name] = (SCRIPTS / name).read_bytes()
        manifest = {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                    for name, data in files.items()}
        files['MANIFEST.json'] = json.dumps({'target': 'fixture-only', 'files': manifest}, indent=2).encode()
        files['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                                     for name, data in files.items()).encode()
        for name, data in files.items():
            (root / name).write_bytes(data)

    def verifier(self, root):
        text = (SCRIPTS / 'install.sh').read_text()
        functions = text[text.index('hash_file(){'):text.index('verify_package "$here"')]
        return subprocess.run(['bash', '-c', 'set -euo pipefail\n' + functions + '\nverify_package "$1"', 'test', str(root)], capture_output=True, text=True)

    def test_valid_complete_package(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d); self.fixture(root)
            result = self.verifier(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_corrupt_core_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d); self.fixture(root); (root / 'easytier-core').write_bytes(b'changed')
            self.assertNotEqual(self.verifier(root).returncode, 0)

    def test_duplicate_and_traversal_checksums_rejected(self):
        for suffix in ['0' * 64 + '  ../outside\n', '0' * 64 + '  install.sh\n']:
            with tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d); self.fixture(root)
                with (root / 'SHA256SUMS').open('a') as f: f.write(suffix)
                self.assertNotEqual(self.verifier(root).returncode, 0)

    def test_manifest_disagreement_rejected_even_with_its_new_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d); self.fixture(root)
            m = json.loads((root / 'MANIFEST.json').read_text()); m['files']['easytier-core']['bytes'] += 1
            data = json.dumps(m, indent=2).encode(); (root / 'MANIFEST.json').write_bytes(data)
            lines = (root / 'SHA256SUMS').read_text().splitlines()
            lines = [hashlib.sha256(data).hexdigest() + '  MANIFEST.json' if l.endswith('  MANIFEST.json') else l for l in lines]
            (root / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
            self.assertNotEqual(self.verifier(root).returncode, 0)

    def test_identity_initialization_precedes_service_creation(self):
        shell = (SCRIPTS / 'installer-common.sh').read_text()
        ps = (SCRIPTS / 'installer-common.ps1').read_text()
        self.assertLess(shell.index('"$version/easytier-core" --managed-state "$state" --managed-status'), shell.index('(set -o noclobber; cat'))
        self.assertLess(ps.index('& "$Version\\easytier-core.exe" --managed-state $State --managed-status'), ps.index('New-Service -Name'))
        self.assertEqual(shell.count('"$version/easytier-core" --managed-state "$state" --managed-status'), 1)

    @unittest.skipUnless(__import__('os').geteuid() == 0, 'fixture owner check requires current root test runner')
    def test_early_staged_receipt_supports_retry_and_absent_rollback(self):
        # Execute only metadata/read/remove helpers against a fresh temporary root.
        # Service and lock adapters are replaced before run_remove is entered.
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d); root = base / 'owned'; root.mkdir(mode=0o700)
            state = base / 'identity-state'; state.mkdir(mode=0o700)
            identity = state / 'identity.json'; identity.write_bytes(b'preserve identity')
            script = (SCRIPTS / 'installer-common.sh').read_text() + r'''
root=$1;state=$2;unit=$3;digest=$(printf "%064d" 0);package_digest=$digest;definition_digest=$digest
write_record staged
load_record
[[ "$status" == staged ]]
operation_lock(){ :; };release_lock(){ :; };cleanup_stage(){ :; };loaded(){ return 1; }
run_remove
'''
            result = subprocess.run(['bash', '-c', script, 'fixture', str(root), str(state), str(base / 'absent.service')], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(identity.read_bytes(), b'preserve identity')
            self.assertIn('Baseline already restored', result.stdout)
            self.assertIn('status\tstaged', (root / 'install-record.tsv').read_text())

    def test_package_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d); self.fixture(root)
            (root / 'easytier-core').rename(root / 'untrusted-core'); (root / 'easytier-core').symlink_to(root / 'untrusted-core')
            self.assertNotEqual(self.verifier(root).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
