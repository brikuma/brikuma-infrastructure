#!/usr/bin/env python3
"""Explicit local install; hooks never download tools."""
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import tarfile
import urllib.request

def install():
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads((root / 'gitleaks.lock.json').read_text())
    arch = {'arm64':'arm64','aarch64':'arm64','x86_64':'x64','AMD64':'x64'}.get(platform.machine())
    entry = manifest['platforms'][platform.system().lower() + '_' + str(arch)]
    destination = root / '.tools' / 'gitleaks' / manifest['version']
    binary = destination / 'gitleaks'
    if binary.is_file() and hashlib.sha256(binary.read_bytes()).hexdigest() == entry['binarySha256']:
        print('Pinned Gitleaks already verified.'); return
    url = 'https://github.com/gitleaks/gitleaks/releases/download/v' + manifest['version'] + '/' + entry['archive']
    data = urllib.request.urlopen(url, timeout=120).read()
    if hashlib.sha256(data).hexdigest() != entry['sha256']: raise ValueError('Archive checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        tool = archive.extractfile('gitleaks').read()
        license_text = archive.extractfile('LICENSE').read()
    if hashlib.sha256(tool).hexdigest() != entry['binarySha256']: raise ValueError('Binary checksum mismatch')
    destination.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(tool); binary.chmod(0o755)
    (destination / 'LICENSE').write_bytes(license_text)
    print('Pinned Gitleaks installed and verified locally.')

if __name__ == '__main__':
    try: install()
    except Exception:
        print('Gitleaks installation failed; raw details withheld.', file=sys.stderr)
        sys.exit(1)
