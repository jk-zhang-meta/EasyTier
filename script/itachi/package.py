#!/usr/bin/env python3
"""Package the exact native build and owned installers; no deployed secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile
import io


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--platform', choices=['windows', 'macos', 'linux'], required=True)
    p.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    source = Path(__file__).resolve().parents[2]
    suffix = '.exe' if a.platform == 'windows' else ''
    release = source / 'target' / a.target / 'release'
    files = {}
    for name in ['easytier-core', 'easytier-cli']:
        files[name + suffix] = (release / (name + suffix)).read_bytes()
    ext = '.ps1' if a.platform == 'windows' else '.sh'
    for name in ['install', 'uninstall', 'rollback', 'installer-common']:
        files[name + ext] = (Path(__file__).parent / (name + ext)).read_bytes()
    if a.platform == 'windows':
        # Distribute only the official, digest-pinned prebuilt driver with its
        # complete prebuilt-binary license, never an unmodified stock core.
        url = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
        digest = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
        with urllib.request.urlopen(url, timeout=60) as f:
            raw = f.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('official Wintun archive digest mismatch')
        member = 'wintun/bin/' + ('arm64' if a.arch == 'aarch64' else 'amd64') + '/wintun.dll'
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            files['wintun.dll'] = z.read(member)
            files['WINTUN-LICENSE.txt'] = z.read('wintun/LICENSE.txt')
        files['DRIVER-PROVENANCE.json'] = json.dumps({
            'archive': url, 'sha256': digest, 'member': member,
            'license_member': 'wintun/LICENSE.txt', 'version': '0.14.1',
        }, indent=2).encode()
    files['LICENSE'] = (source / 'LICENSE').read_bytes()
    files['README.txt'] = (
        'EasyTier Itachi native managed network\n'
        'Default authority: https://www.itachi.fans\n'
        'Source: https://github.com/jk-zhang-meta/EasyTier\n'
        'Windows: open an elevated PowerShell and run ./install.ps1\n'
        'Linux/macOS: sudo bash ./install.sh\n'
        'The installer enables an OS startup/background service.\n'
        'Fresh installation and identical-package reinstallation only; other upgrades are rejected.\n'
        'Rollback removes this owned fresh service and preserves the device identity.\n'
        'Approve the printed public identity in PersonalWeb before use.\n'
        'No fleet-wide key, password or user private key is included.\n'
        'Unix servers: explicit --relay --prepare prints a real public identity without starting a service.\n'
        'Then issue a device-key/address-bound one-use invitation in the authority; resume the same package/public options with --relay-invitation-file PRIVATE_FILE.\n'
        'See docs/itachi/implementation-status.md in the source for server provisioning.\n'
        'Uninstall removes only this service, preserving the identity.\n'
        'Joining the overlay does not enable or bypass OS SSH/RDP login.\n'
    ).encode()
    manifest = {n: {'sha256': hashlib.sha256(d).hexdigest(), 'bytes': len(d)} for n, d in files.items()}
    files['MANIFEST.json'] = json.dumps({'target': a.target, 'files': manifest}, indent=2).encode()
    files['SHA256SUMS'] = ''.join(hashlib.sha256(d).hexdigest() + '  ' + n + '\n' for n, d in files.items()).encode()
    a.output.mkdir(parents=True, exist_ok=True)
    dest = a.output / ('easytier-itachi-' + a.platform + '-' + a.arch + '.zip')
    with zipfile.ZipFile(dest, 'x', zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            info = zipfile.ZipInfo(n)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if n in ['easytier-core', 'easytier-cli'] or n.endswith('.sh') else 0o644
            info.external_attr = (0o100000 | mode) << 16
            z.writestr(info, d)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    dest.with_suffix('.zip.sha256').write_text(digest + '  ' + dest.name + '\n')
    print(dest.name, digest, dest.stat().st_size)


if __name__ == '__main__':
    main()
