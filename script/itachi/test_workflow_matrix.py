#!/usr/bin/env python3
"""Closed JSON matrix/dispatch contract checks; no builds, services or dependencies."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/itachi-managed.yml'
EXPECTED = [
    {'os': 'ubuntu-24.04', 'target': 'x86_64-unknown-linux-musl', 'platform': 'linux', 'arch': 'x86_64'},
    {'os': 'ubuntu-24.04-arm', 'target': 'aarch64-unknown-linux-musl', 'platform': 'linux', 'arch': 'aarch64'},
    {'os': 'macos-15-intel', 'target': 'x86_64-apple-darwin', 'platform': 'macos', 'arch': 'x86_64'},
    {'os': 'macos-latest', 'target': 'aarch64-apple-darwin', 'platform': 'macos', 'arch': 'aarch64'},
    {'os': 'windows-latest', 'target': 'x86_64-pc-windows-msvc', 'platform': 'windows', 'arch': 'x86_64'},
    {'os': 'windows-11-arm', 'target': 'aarch64-pc-windows-msvc', 'platform': 'windows', 'arch': 'aarch64'},
]


def cases(text):
    found = re.search(r"fromJSON\(inputs\.platform == 'windows' &&\s*'(\[.*?\])' \|\|\s*'(\[.*?\])'\)", text, re.S)
    if not found:
        raise ValueError('Expected exactly two closed fromJSON branches')
    return json.loads(found[1]), json.loads(found[2])


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.windows, self.all = cases(self.text)

    def test_default_and_all_keep_exact_original_six(self):
        self.assertEqual(self.all, EXPECTED)
        self.assertRegex(self.text, r'type: choice\s+default: all\s+options:\s+- all\s+- windows')
        for value in ('all', '', None):
            self.assertEqual(self.windows if value == 'windows' else self.all, EXPECTED)

    def test_windows_selects_exactly_both_windows_arches(self):
        self.assertEqual(self.windows, EXPECTED[-2:])
        self.assertEqual({r['arch'] for r in self.windows}, {'x86_64', 'aarch64'})

    def test_parallelism_and_native_features_preserved(self):
        self.assertIn('fail-fast: false\n      max-parallel: 2', self.text)
        self.assertIn('runs-on: ${{ matrix.os }}', self.text)
        self.assertIn('timeout-minutes: 60', self.text)
        self.assertIn('--features management,tun,ring-crypto,cli,icmp-proxy,websocket,smoltcp', self.text)
        self.assertIn('retention-days: 14', self.text)

    def test_regression_precedes_real_windows_service_smoke(self):
        start = self.text.index('- name: Verify Windows startup')
        body = self.text[start:]
        self.assertLess(body.index('test_install_record.ps1'), body.index('& ./smoke-client/install.ps1'))
        self.assertEqual(body.count('& ./smoke-client/install.ps1'), 2)
        self.assertIn('& ./smoke-client/rollback.ps1', body)

    def test_only_closed_constants_not_dispatch_values_in_commands(self):
        self.assertEqual(self.text.count('inputs.platform'), 1)
        self.assertNotIn('${{ inputs.platform }}', self.text)
        self.assertTrue(all(set(r) == {'os', 'target', 'platform', 'arch'} for r in self.all))

    def test_receipt_replacement_uses_native_clr_null(self):
        text = (ROOT / 'script/itachi/installer-common.ps1').read_text()
        self.assertIn('[IO.File]::Replace($Tmp,$RecordPath,[System.Management.Automation.Language.NullString]::Value)', text)
        self.assertNotIn('[IO.File]::Replace($Tmp,$RecordPath,$null)', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
