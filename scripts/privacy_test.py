"""Behavioral tests use disposable repositories and synthetic canaries only."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import random
import string

SCRIPT = Path(__file__).with_name('privacy.py')
spec = importlib.util.spec_from_file_location('privacy', SCRIPT)
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)

class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='brikuma-privacy-test-')
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Privacy Test')
        self.git('config', 'user.email', '123+privacy-test@users.noreply.github.com')
        (self.repo / 'README.md').write_text('Synthetic privacy test.\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.canary = 'private-canary' + '@' + 'mail.invalid'
        self.secret = 'ghp_' + ''.join(random.Random(713).choices(string.ascii_letters + string.digits, k=36))

    def git(self, *args, env=None):
        result = subprocess.run(['git', '-C', str(self.repo), *args], capture_output=True,
                                text=True, env={**os.environ, **(env or {})})
        self.assertEqual(result.returncode, 0, 'Fixture Git operation failed')
        return result.stdout

    def commit(self, message='test(docs): exercise privacy', env=None):
        self.git('add', '--all')
        self.git('commit', '-qm', message, env=env)
        return self.git('rev-parse', 'HEAD').strip()

    def scan(self, *args, input_text=None, env=None):
        result = subprocess.run(['python3', '-B', str(SCRIPT), *args, '--repo', str(self.repo)],
                                input=input_text, text=True, capture_output=True,
                                env={**os.environ, **(env or {})})
        self.assertNotIn(self.canary, result.stdout + result.stderr)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        self.assertNotIn(str(self.repo), result.stdout + result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_clean_repository_and_common_code_are_accepted(self):
        (self.repo / 'example.txt').write_text('\n'.join(['npm@10.9.8', '@AGENTS.md', '/api/users/123', 'user@example.com']))
        self.commit()
        code, report = self.scan('full')
        self.assertEqual(code, 0)
        self.assertEqual(report['coverage']['commits'], 2)

    def test_author_committer_and_trailer_are_checked(self):
        for field in ['GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_EMAIL']:
            (self.repo / field).write_text('Synthetic.\n')
            self.commit(env={field: self.canary})
        (self.repo / 'trailer').write_text('Synthetic.\n')
        self.commit('test(docs): synthetic trailer\n\nCo-authored-by: Canary <' + self.canary + '>')
        code, report = self.scan('range', '--base', self.base)
        self.assertEqual(code, 1)
        places = {f['location'] for f in report['findings']}
        self.assertTrue({'author','committer','commit-message'} <= places)

    def test_deleted_intermediate_secret_and_private_file_are_detected(self):
        (self.repo / 'removed.txt').write_text(self.secret + '\n' + self.canary)
        first = self.commit()
        (self.repo / 'removed.txt').unlink()
        self.commit()
        code, report = self.scan('range', '--base', self.base)
        self.assertEqual(code, 1)
        self.assertTrue(any(f['category'].startswith('secret-') and f['reference'] == first for f in report['findings']))

    def test_all_push_updates_and_new_branch_ancestry_are_checked(self):
        (self.repo / 'removed').write_text(self.canary)
        bad = self.commit()
        (self.repo / 'removed').unlink()
        head = self.commit()
        data = f'refs/heads/first {head} refs/heads/first {"0" * 40}\nrefs/heads/second {bad} refs/heads/second {self.base}\n'
        code, report = self.scan('pre-push', input_text=data)
        self.assertEqual(code, 1)
        self.assertTrue(any(f['reference'] == bad for f in report['findings']))

    def test_private_ref_name_is_rejected(self):
        ref = 'refs/heads/' + self.canary
        code, report = self.scan('pre-push', input_text=f'{ref} {self.base} {ref} {"0" * 40}\n')
        self.assertEqual(code, 1)
        self.assertIn('ref-name', {f['location'] for f in report['findings']})

    def test_staged_snapshot_ignores_unstaged_cleanup(self):
        (self.repo / 'staged.txt').write_text(self.canary)
        self.git('add', 'staged.txt')
        (self.repo / 'staged.txt').write_text('Clean unstaged contents.\n')
        code, _ = self.scan('staged')
        self.assertEqual(code, 1)

    def test_commit_message_and_effective_identity_are_checked(self):
        message = self.repo / '.git' / 'COMMIT_EDITMSG'
        message.write_text('test(docs): fixture\n\nSigned-off-by: Canary <' + self.canary + '>')
        code, _ = self.scan('message', '--message', str(message), env={'GIT_COMMITTER_EMAIL': self.canary})
        self.assertEqual(code, 1)

    def test_all_platform_home_paths_and_filename_are_redacted(self):
        (self.repo / self.canary).write_text('/' + 'Users' + '/private-canary/source\n/' + 'home' + '/private-canary/source\nC:' + '\\' + 'Users' + '\\private-canary\\source')
        self.commit()
        code, report = self.scan('full')
        self.assertEqual(code, 1)
        self.assertEqual(sum(f['category'] == 'personal-path' for f in report['findings']), 3)
        self.assertTrue(all(f['location'].startswith('redacted-location-') for f in report['findings']))

    def test_annotated_tag_identity_and_message_are_checked(self):
        self.git('tag', '-a', 'test-tag', '-m', self.canary, env={'GIT_COMMITTER_EMAIL': self.canary})
        code, report = self.scan('full')
        self.assertEqual(code, 1)
        self.assertIn('annotated-tag', {f['location'] for f in report['findings']})

    def test_pr_cannot_disable_scanner_using_repository_config(self):
        (self.repo / '.gitleaks.toml').write_text('title = "disabled"\n')
        (self.repo / 'credentials.txt').write_text(self.secret + ' # gitleaks:allow\n')
        self.commit()
        code, report = self.scan('range', '--base', self.base, env={'GITLEAKS_CONFIG_TOML':'title = "disabled"'})
        self.assertEqual(code, 1)
        self.assertTrue(any(f['category'].startswith('secret-') for f in report['findings']))

    def test_integration_tree_is_scanned(self):
        (self.repo / 'integration.txt').write_text(self.canary)
        integration = self.commit()
        code, report = self.scan('range', '--base', self.base, '--head', self.base, '--integration', integration)
        self.assertEqual(code, 1)
        self.assertTrue(any(f['reference'] == integration for f in report['findings']))

    def test_missing_history_fails_closed_without_echoing_input(self):
        code, report = self.scan('range', '--base', self.canary)
        self.assertEqual(code, 2)
        self.assertEqual(report['status'], 'blocked')

    def test_binary_tampering_is_refused(self):
        policy = self.repo / 'policy'; policy.mkdir()
        for name in ['privacy-policy.json', 'gitleaks.lock.json']:
            (policy / name).write_bytes((privacy.POLICY_ROOT / name).read_bytes())
        manifest = json.loads((policy / 'gitleaks.lock.json').read_text())
        binary = policy / '.tools' / 'gitleaks' / manifest['version'] / 'gitleaks'
        binary.parent.mkdir(parents=True); binary.write_text('not the scanner')
        scan = privacy.Scanner(self.repo, policy)
        with self.assertRaises(privacy.ScanError): scan.result()

    def test_secret_filename_never_appears_in_any_finding(self):
        (self.repo / (self.secret + '.txt')).write_text(self.canary)
        self.commit()
        code, report = self.scan('full')
        self.assertEqual(code, 1)
        self.assertTrue(all(f['location'].startswith('redacted-location-') for f in report['findings']))

    def test_utf16_and_json_escaped_windows_paths_are_checked(self):
        (self.repo / 'utf16.txt').write_bytes(self.canary.encode('utf-16'))
        (self.repo / 'windows.json').write_text(json.dumps({'file':'C:' + '\\' + 'Users' + '\\private-canary\\source'}))
        self.commit()
        code, report = self.scan('full')
        self.assertEqual(code, 1)
        self.assertTrue({'private-email','personal-path'} <= {f['category'] for f in report['findings']})

    def test_detached_head_is_included(self):
        self.git('checkout', '-q', '--detach')
        (self.repo / 'detached.txt').write_text(self.canary)
        detached = self.commit()
        code, report = self.scan('full')
        self.assertEqual(code, 1)
        self.assertTrue(any(f['reference'] == detached for f in report['findings']))

    def test_utf16_and_utf32_secrets_are_detected_without_an_email(self):
        for encoding in ['utf-16', 'utf-16-le', 'utf-16-be', 'utf-32']:
            with self.subTest(encoding=encoding):
                (self.repo / 'encoded.txt').write_bytes(self.secret.encode(encoding))
                head = self.commit()
                code, report = self.scan('range', '--base', self.base)
                self.assertEqual(code, 1)
                self.assertTrue(any(f['category'].startswith('secret-') and f['reference'] == head for f in report['findings']))

    def test_extra_commit_headers_are_checked(self):
        original = self.git('cat-file', 'commit', self.base)
        headers, message = original.split('\n\n', 1)
        raw = headers + '\nmergetag object ' + self.base + '\n tagger Synthetic <' + self.canary + '> 1 +0000\n\n' + message
        result = subprocess.run(['git', '-C', str(self.repo), 'hash-object', '-t', 'commit', '-w', '--stdin'], input=raw, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.git('update-ref', 'refs/heads/extra-header', result.stdout.strip())
        code, report = self.scan('full')
        self.assertEqual(code, 1)
        self.assertIn('commit-headers', {f['location'] for f in report['findings']})

    def test_tagger_identity_without_dotted_domain_is_rejected(self):
        self.git('tag', '-a', 'short-domain', '-m', 'Synthetic tag', env={'GIT_COMMITTER_EMAIL':'private' + '@' + 'localhost'})
        code, report = self.scan('full')
        self.assertEqual(code, 1)
        self.assertIn('tagger', {f['location'] for f in report['findings']})

    def test_public_dependabot_trailer_does_not_allow_a_private_author(self):
        (self.repo / 'bot.txt').write_text('Synthetic fixture.\n')
        trailer = 'test(docs): public service attribution\n\nSigned-off-by: dependabot[bot] <support@github.com>'
        self.commit(trailer)
        code, _ = self.scan('full')
        self.assertEqual(code, 0)
        (self.repo / 'bot.txt').write_text('Changed fixture.\n')
        self.commit(trailer, env={'GIT_AUTHOR_EMAIL': 'support@github.com'})
        code, report = self.scan('range', '--base', self.base)
        self.assertEqual(code, 1)
        self.assertIn('author', {f['location'] for f in report['findings']})

if __name__ == '__main__':
    unittest.main()
