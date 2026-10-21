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
        # Use only the driver DLL from the digest-verified upstream release;
        # never substitute upstream's unmodified core for this fork's build.
        url = 'https://api.github.com/repos/EasyTier/EasyTier/releases/tags/v2.7.0'
        req = urllib.request.Request(url, headers={'User-Agent': 'EasyTier-Itachi-packager'})
        with urllib.request.urlopen(req, timeout=30) as f:
            metadata = json.loads(f.read(2 * 1024 * 1024))
        upstream_arch = 'arm64' if a.arch == 'aarch64' else a.arch
        name = 'easytier-windows-' + upstream_arch + '-v2.7.0.zip'
        asset = next(x for x in metadata['assets'] if x['name'] == name)
        digest = asset['digest']
        if not digest or not digest.startswith('sha256:') or asset['size'] > 100 * 1024 * 1024:
            raise ValueError('unverified upstream driver archive')
        with urllib.request.urlopen(asset['browser_download_url'], timeout=90) as f:
            raw = f.read(asset['size'] + 1)
        if len(raw) != asset['size'] or 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('upstream archive digest mismatch')
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = [n for n in z.namelist() if Path(n).name.lower() == 'wintun.dll']
            if len(names) != 1:
                raise ValueError('ambiguous driver DLL')
            files['wintun.dll'] = z.read(names[0])
        files['DRIVER-PROVENANCE.json'] = json.dumps({
            'archive': asset['browser_download_url'], 'sha256': digest.split(':')[1],
            'member': names[0],
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
