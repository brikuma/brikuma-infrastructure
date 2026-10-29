#!/usr/bin/env python3
"""Fail closed on private identities, personal paths and secrets; never print matches."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

POLICY_ROOT = Path(__file__).resolve().parent.parent
EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!#$%&'*+/=?^_{|}~\[\]-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
NOREPLY = re.compile(r"(?:\d+\+)?[A-Za-z0-9-]+(?:\[bot\])?@users\.noreply\.github\.com", re.I)
HOME = re.compile(r"(?:/(?:Users|home)/[^\s/<>\"'`]+|(?i:[A-Za-z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[^\s\\/<>\"'`]+))")
CONVERSATION = re.compile(r"https?://(?:chatgpt\.com|chat\.openai\.com)/(?:share|c|g|s)/[^\s<>\"')]+", re.I)
OID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
ZERO = {'0' * 40, '0' * 64}

class ScanError(Exception):
    pass

def git(repo, *args, data=None):
    env = {**os.environ, 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_CONFIG_NOSYSTEM': '1'}
    result = subprocess.run(['git', '-C', str(repo), *args], input=data, capture_output=True, env=env)
    if result.returncode:
        raise ScanError('Git input is unavailable or invalid; fetch the exact required revisions.')
    return result.stdout

def resolve(repo, ref):
    value = git(repo, 'rev-parse', '--verify', '--end-of-options', ref).decode().strip()
    if not OID.fullmatch(value):
        raise ScanError('Expected an exact Git object.')
    return value

def private_email(value, identity=False):
    if NOREPLY.fullmatch(value):
        return False
    # GitHub's signed web merge committer. Other bot exceptions need explicit review.
    if value == 'noreply@github.com':
        return False
    if not identity and value == 'support@github.com':
        return False
    if not identity and value.rsplit('@', 1)[-1].lower() in {'example.com', 'example.org', 'example.net', 'example.invalid'}:
        return False
    return True

def categories(text, identity=False):
    result = set()
    if any(private_email(m.group(), identity) for m in EMAIL.finditer(text)):
        result.add('private-email')
    if HOME.search(text): result.add('personal-path')
    if CONVERSATION.search(text): result.add('conversation-link')
    return result

def safe_location(value):
    if categories(value) or any(ord(c) < 32 for c in value):
        return 'redacted-location-' + hashlib.sha256(value.encode()).hexdigest()[:12]
    return value

class Scanner:
    def __init__(self, repo, policy_root=POLICY_ROOT):
        self.repo = Path(repo).resolve()
        self.policy_root = Path(policy_root)
        self.policy = json.loads((self.policy_root / 'privacy-policy.json').read_text())
        self.identifier = self.policy['repository']
        if not re.fullmatch(r'brikuma(?:-frontend|-backend|-infrastructure)?', self.identifier):
            raise ScanError('Repository identifier is invalid.')
        self.findings = []
        self.payloads = {}
        self.locations = {}
        self.filename_tokens = {}
        self.sensitive_locations = set()
        self.seen_commits = set()
        self.seen_trees = set()
        self.seen_tags = set()
        self.counts = {'commits': 0, 'tags': 0, 'trees': 0, 'blobs': 0}

    def add(self, category, ref, location, line=1):
        finding = {'repository': self.identifier, 'reference': ref,
                   'location': safe_location(location), 'line': line,
                   'category': category, 'severity': 'high', 'resolution': 'unresolved'}
        if finding not in self.findings: self.findings.append(finding)

    def inspect(self, data, ref, location, object_id=None, identity=False):
        views = [data]
        if data.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
            views.append(data.decode('utf-32', errors='replace').encode('utf-8'))
        elif data.startswith((b'\xff\xfe', b'\xfe\xff')):
            views.append(data.decode('utf-16', errors='replace').encode('utf-8'))
        elif b'\0' in data:
            views.append(data.replace(b'\0', b''))
        allowances = self.policy.get('reviewedPublicBlobs', {}).get(object_id, {})
        for view in dict.fromkeys(views):
            text = view.decode('utf-8', errors='replace')
            for line, value in enumerate(text.splitlines(), 1):
                if location == 'commit-message' and value.strip() == 'Signed-off-by: dependabot[bot] <support@github.com>':
                    continue  # Public service attribution, never an identity exception.
                for category in categories(value, identity):
                    # Only exact immutable blob/category approvals; never identity or secrets.
                    if category in allowances and not identity: continue
                    self.add(category, ref, location, line)
            token = hashlib.sha256(view).hexdigest()
            self.payloads[token] = view
            self.locations.setdefault(token, (ref, location))

    def tree(self, tree, ref):
        if tree in self.seen_trees: return
        self.seen_trees.add(tree)
        self.counts['trees'] += 1
        for entry in git(self.repo, 'ls-tree', '-rz', tree).split(b'\0'):
            if not entry: continue
            metadata, filename = entry.split(b'\t', 1)
            mode, kind, oid = metadata.decode().split()
            name = filename.decode('utf-8', errors='replace')
            self.inspect(filename, ref, name + ' (filename)')
            self.filename_tokens[hashlib.sha256(filename).hexdigest()] = name
            if kind != 'blob': continue  # Gitlinks are scanned in their owning repositories.
            if oid not in self.locations:
                self.locations[oid] = (ref, name)
                self.counts['blobs'] += 1
                self.inspect(git(self.repo, 'cat-file', 'blob', oid), ref, name, oid)

    def commit(self, oid):
        if oid in self.seen_commits: return
        self.seen_commits.add(oid)
        self.counts['commits'] += 1
        data = git(self.repo, 'cat-file', 'commit', oid)
        headers, message = data.split(b'\n\n', 1)
        self.inspect(headers, oid, 'commit-headers', identity=True)
        self.inspect(message, oid, 'commit-message', identity=True)
        for line in headers.splitlines():
            if line.startswith((b'author ', b'committer ')):
                self.inspect(line, oid, line.split(b' ', 1)[0].decode(), identity=True)
                email = re.search(rb'<([^<>]*)>', line)
                if email is None or private_email(email[1].decode(errors='replace'), True):
                    self.add('private-email', oid, line.split(b' ', 1)[0].decode())
        tree = headers.splitlines()[0].split()[1].decode()
        self.tree(tree, oid)

    def revision(self, ref, base=None):
        oid = resolve(self.repo, ref)
        kind = git(self.repo, 'cat-file', '-t', oid).decode().strip()
        while kind == 'tag':
            if oid in self.seen_tags: return
            self.seen_tags.add(oid)
            self.counts['tags'] += 1
            data = git(self.repo, 'cat-file', 'tag', oid)
            self.inspect(data, oid, 'annotated-tag', identity=True)
            for line in data.split(b'\n\n', 1)[0].splitlines():
                if line.startswith(b'tagger '):
                    email = re.search(rb'<([^<>]*)>', line)
                    if email is None or private_email(email[1].decode(errors='replace'), True):
                        self.add('private-email', oid, 'tagger')
            oid = data.splitlines()[0].split()[1].decode()
            kind = git(self.repo, 'cat-file', '-t', oid).decode().strip()
        if kind == 'tree': self.tree(oid, oid); return
        if kind == 'blob': self.inspect(git(self.repo, 'cat-file', 'blob', oid), oid, 'tagged-blob', oid); return
        if kind != 'commit': raise ScanError('Unsupported Git object type.')
        args = ['rev-list', oid]
        if base: args += ['^' + resolve(self.repo, base + '^{commit}')]
        args += ['--']
        for commit in git(self.repo, *args).decode().splitlines(): self.commit(commit)
        # Inspect the actual integration tree even for an empty introduced range.
        self.tree(resolve(self.repo, oid + '^{tree}'), oid)

    def full(self, all_objects=False):
        self.revision('HEAD')
        for entry in git(self.repo, 'for-each-ref', '--format=%(objectname) %(refname)').decode().splitlines():
            oid, name = entry.split(' ', 1)
            self.inspect(name.encode(), oid, 'ref-name')
            self.revision(oid)
        if all_objects:
            for entry in git(self.repo, 'cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)').decode().splitlines():
                oid, kind = entry.split()
                if kind == 'commit': self.commit(oid)
                elif kind == 'tag': self.revision(oid)
                elif kind == 'tree': self.tree(oid, oid)
                elif kind == 'blob' and oid not in self.locations:
                    self.counts['blobs'] += 1
                    self.locations[oid] = (oid, 'unreferenced-blob')
                    self.inspect(git(self.repo, 'cat-file', 'blob', oid), oid, 'unreferenced-blob', oid)

    def identities(self):
        for kind in ['GIT_AUTHOR_IDENT', 'GIT_COMMITTER_IDENT']:
            data = git(self.repo, 'var', kind)
            self.inspect(data, 'index', kind, identity=True)
            email = re.search(rb'<([^<>]*)>', data)
            if email is None or private_email(email[1].decode(errors='replace'), True):
                self.add('private-email', 'index', kind)

    def secrets(self):
        import platform
        arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'x64', 'AMD64': 'x64'}.get(platform.machine())
        key = platform.system().lower() + '_' + str(arch)
        manifest = json.loads((self.policy_root / 'gitleaks.lock.json').read_text())
        binary = self.policy_root / '.tools' / 'gitleaks' / manifest['version'] / 'gitleaks'
        expected = manifest['platforms'].get(key, {}).get('binarySha256')
        if not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != expected:
            raise ScanError('Pinned Gitleaks is missing or changed. Run python3 scripts/privacy-install.py outside hooks.')
        with tempfile.TemporaryDirectory(prefix='brikuma-privacy-') as directory:
            root = Path(directory)
            inputs = root / 'inputs'; inputs.mkdir()
            for token, data in self.payloads.items(): (inputs / token).write_bytes(data)
            config = root / 'gitleaks.toml'
            config.write_text('[extend]\nuseDefault = true\n')
            ignore = root / 'empty-ignore'; ignore.write_text('')
            report = root / 'report.json'
            env = {k:v for k,v in os.environ.items() if not k.startswith('GITLEAKS_')}
            result = subprocess.run([str(binary), 'dir', str(inputs), '--config', str(config),
                '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow', '--redact=100',
                '--no-banner', '--no-color', '--log-level', 'error', '--max-archive-depth', '4',
                '--max-decode-depth', '5', '--report-format', 'json', '--report-path', str(report)],
                capture_output=True, env=env, cwd=root)
            if result.returncode not in (0, 1) or not report.is_file():
                raise ScanError('Gitleaks did not complete; raw diagnostics withheld.')
            for item in json.loads(report.read_text()):
                token = next((part for part in Path(item['File']).parts if part in self.payloads), None)
                if token is None: raise ScanError('Gitleaks returned an unknown input; diagnostics withheld.')
                ref, location = self.locations[token]
                if token in self.filename_tokens:
                    name = self.filename_tokens[token]
                    self.sensitive_locations.update([name, name + ' (filename)'])
                self.add('secret-' + re.sub(r'[^a-z0-9-]', '', item['RuleID']), ref, location, item.get('StartLine', 1))
            if result.returncode == 1 and not self.findings:
                raise ScanError('Gitleaks reported an unclassified finding.')

    def result(self):
        self.secrets()
        for finding in self.findings:
            if finding['location'] in self.sensitive_locations:
                finding['location'] = 'redacted-location-' + hashlib.sha256(finding['location'].encode()).hexdigest()[:12]
        return {'schemaVersion': 1, 'repository': self.identifier, 'coverage': self.counts,
                'status': 'failed' if self.findings else 'passed', 'findings': self.findings}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['full', 'range', 'staged', 'message', 'pre-push'])
    parser.add_argument('--repo', default='.')
    parser.add_argument('--base'); parser.add_argument('--head', default='HEAD')
    parser.add_argument('--integration'); parser.add_argument('--message')
    parser.add_argument('--all-objects', action='store_true')
    parser.add_argument('--report')
    args = parser.parse_args()
    try:
        scan = Scanner(args.repo)
        if git(scan.repo, 'rev-parse', '--is-shallow-repository').strip() == b'true':
            raise ScanError('Shallow history cannot establish privacy coverage; fetch full history.')
        if args.mode == 'full': scan.full(args.all_objects)
        elif args.mode == 'range':
            if not args.base: raise ScanError('An exact base revision is required.')
            scan.revision(args.head, args.base)
            if args.integration: scan.commit(resolve(scan.repo, args.integration + '^{commit}'))
        elif args.mode == 'staged':
            scan.identities(); scan.tree(git(scan.repo, 'write-tree').decode().strip(), 'index')
        elif args.mode == 'message':
            if not args.message: raise ScanError('A commit message file is required.')
            scan.identities(); scan.inspect(Path(args.message).read_bytes(), 'index', 'commit-message', identity=True)
        else:
            updates = sys.stdin.read().splitlines()
            for update in updates:
                local_ref, local_sha, remote_ref, remote_sha = update.split()
                scan.inspect((local_ref + '\n' + remote_ref).encode(), 'push', 'ref-name')
                if local_sha in ZERO: continue
                if not OID.fullmatch(local_sha) or not OID.fullmatch(remote_sha): raise ScanError('Invalid push input.')
                scan.revision(local_sha, None if remote_sha in ZERO else remote_sha)
        report = scan.result()
        output = json.dumps(report, indent=2) + '\n'
        if args.report: Path(args.report).write_text(output)
        print(output, end='')
        return int(bool(scan.findings))
    except (ScanError, OSError, ValueError, KeyError) as error:
        # Never echo arbitrary paths, subprocess output, policy contents or exceptions.
        print(json.dumps({'status': 'blocked', 'reason': str(error) if isinstance(error, ScanError) else 'Invalid or unavailable scanner input; raw details withheld.'}))
        return 2

if __name__ == '__main__':
    sys.exit(main())
