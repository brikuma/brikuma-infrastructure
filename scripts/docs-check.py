#!/usr/bin/env python3
"""Check the indexed documentation tree without runtime dependencies."""
import argparse
import json
from pathlib import Path
import posixpath
import re
import subprocess
import sys
from urllib.parse import unquote

def git(*args):
    result = subprocess.run(['git', *args], capture_output=True, text=True)
    if result.returncode: raise ValueError('Documentation Git input unavailable.')
    return result.stdout

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--message'); args = parser.parse_args()
    if args.message:
        first = Path(args.message).read_text().splitlines()[0]
        if not re.fullmatch(r'(?:docs|ci|chore|fix|test)\((?:docs|quality|tooling|deps)\): [^\r\n]{1,90}', first):
            raise ValueError('Use an English Conventional Commit with an owning documentation/tooling scope.')
        return
    tree = git('write-tree').strip()
    files = set(git('ls-tree', '-r', '--name-only', tree).splitlines())
    contents = {name:git('show', tree + ':' + name) for name in files if name.endswith('.md')}
    conditional = set(json.loads(git('show', tree + ':docs/link-policy.json'))['parentLinks'])
    failures = 0; unavailable = set()
    for source, text in contents.items():
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
            if re.match(r'(?:https?://|mailto:)', target): continue
            filename, _, anchor = target.partition('#')
            name = posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(filename))) if filename else source
            if name.startswith('../'):
                if (source + ':' + target) in conditional: unavailable.add(name)
                else: failures += 1
                continue
            if name not in files and not any(f.startswith(name.rstrip('/') + '/') for f in files):
                failures += 1; continue
            if anchor and name in contents:
                headings = {re.sub(r'[^\w\s-]', '', line.lstrip('#').strip().lower()).replace(' ', '-')
                            for line in contents[name].splitlines() if re.match(r'^#{1,6} ', line)}
                if anchor not in headings: failures += 1
        for imported in re.findall(r'^@(.+\.md)$', text, re.M):
            name = posixpath.normpath(posixpath.join(posixpath.dirname(source), imported))
            if name.startswith('../'):
                if source + ':' + imported not in conditional: failures += 1
                else: unavailable.add(name)
            elif name not in files: failures += 1
    if failures: raise ValueError('Documentation contains unresolved local links or undeclared parent links.')
    print(json.dumps({'status':'passed','tree':tree,'markdownFiles':len(contents),
                      'parentGovernance':'not verified in standalone check' if unavailable else 'not referenced'}))

if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError):
        print('Documentation check failed; inspect indexed links, policy and commit message.', file=sys.stderr)
        sys.exit(1)
