"""Exercise indexed documentation failures with disposable synthetic repositories."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('docs-check.py')

class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='brikuma-docs-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        (self.root / 'docs').mkdir()
        (self.root / 'docs/link-policy.json').write_text(json.dumps({'parentLinks':[]}))
        (self.root / 'README.md').write_text('# Start\n')

    def git(self, *args):
        result = subprocess.run(['git', *args], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 0)

    def scan(self):
        return subprocess.run(['python3', '-B', str(SCRIPT)], cwd=self.root, capture_output=True).returncode

    def test_valid_links_and_anchor(self):
        (self.root / 'README.md').write_text('# Start\n[Details](docs/details.md#detail)\n')
        (self.root / 'docs/details.md').write_text('# Detail\n[Home](../README.md)\n')
        self.git('add', '.')
        self.assertEqual(self.scan(), 0)

    def test_unstaged_fix_cannot_hide_indexed_broken_link(self):
        (self.root / 'README.md').write_text('[Missing](missing.md)\n')
        self.git('add', '.')
        (self.root / 'README.md').write_text('# Fixed only outside the index\n')
        self.assertEqual(self.scan(), 1)

    def test_missing_anchor_is_rejected(self):
        (self.root / 'README.md').write_text('# Start\n[Missing](#absent)\n')
        self.git('add', '.')
        self.assertEqual(self.scan(), 1)

    def test_parent_links_need_exact_policy(self):
        (self.root / 'README.md').write_text('[Governance](../AGENTS.md)\n')
        self.git('add', '.')
        self.assertEqual(self.scan(), 1)
        (self.root / 'docs/link-policy.json').write_text(json.dumps({'parentLinks':['README.md:../AGENTS.md']}))
        self.git('add', '.')
        self.assertEqual(self.scan(), 0)

    def test_missing_instruction_import_is_rejected(self):
        (self.root / 'CLAUDE.md').write_text('@missing.md\n')
        self.git('add', '.')
        self.assertEqual(self.scan(), 1)

    def test_hook_installation_preserves_existing_default_hooks(self):
        hook=self.root / '.git/hooks/pre-commit'
        hook.write_text('#!/bin/sh\nexit 0\n'); hook.chmod(0o755)
        result=subprocess.run(['python3','-B',str(SCRIPT.with_name('install-hooks.py'))],cwd=self.root,capture_output=True)
        self.assertNotEqual(result.returncode,0)
        current=subprocess.run(['git','config','--local','--get','core.hooksPath'],cwd=self.root,capture_output=True)
        self.assertNotEqual(current.returncode,0)

    def test_hook_installation_preserves_inherited_configuration(self):
        import os
        config=self.root / 'synthetic-global-config'
        config.write_text('[core]\n    hooksPath = existing-hooks\n')
        result=subprocess.run(['python3','-B',str(SCRIPT.with_name('install-hooks.py'))],cwd=self.root,capture_output=True,env={**os.environ,'GIT_CONFIG_GLOBAL':str(config)})
        self.assertNotEqual(result.returncode,0)
        current=subprocess.run(['git','config','--local','--get','core.hooksPath'],cwd=self.root,capture_output=True)
        self.assertNotEqual(current.returncode,0)

if __name__ == '__main__':
    unittest.main()
