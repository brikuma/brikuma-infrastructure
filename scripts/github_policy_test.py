"""Audit behavior tests use synthetic API responses and never call GitHub."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('github-policy.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads((policy.ROOT / '.github/repository-policy.json').read_text())
        self.prefix = 'repos/brikuma/' + self.expected['repository']
        self.responses = {
            self.prefix:self.expected['settings'],
            self.prefix+'/actions/permissions/workflow':self.expected['workflowPermissions'],
            self.prefix+'/actions/permissions/fork-pr-contributor-approval':self.expected['forkApproval'],
            self.prefix+'/vulnerability-alerts':{},
            self.prefix+'/automated-security-fixes':{'enabled':True,'paused':False},
            self.prefix+'/private-vulnerability-reporting':{'enabled':True},
            self.prefix+'/rulesets?per_page=100':[{'name':r['name'],'id':i} for i,r in enumerate(self.expected['rulesets'])],
        }
        self.responses.update({self.prefix+'/rulesets/'+str(i):r for i,r in enumerate(self.expected['rulesets'])})

    def run_audit(self, public=False):
        def api(endpoint):
            value=self.responses.get(endpoint)
            if value is None: raise ValueError('Synthetic unavailable surface')
            return value
        output=io.StringIO()
        with patch.object(policy,'api',api), patch.object(sys,'argv',['policy','audit']+(['--public-only'] if public else [])), contextlib.redirect_stdout(output):
            status=policy.main()
        return status,json.loads(output.getvalue())

    def test_complete_policy_matches(self):
        self.assertEqual(self.run_audit()[0],0)

    def test_disabled_alerts_fail_administrative_audit(self):
        del self.responses[self.prefix+'/vulnerability-alerts']
        code, report=self.run_audit()
        self.assertEqual(code,1)
        self.assertTrue(any(f['surface']=='dependabot-alerts' for f in report['findings']))

    def test_paused_security_updates_fail(self):
        self.responses[self.prefix+'/automated-security-fixes']['paused']=True
        self.assertEqual(self.run_audit()[0],1)

    def test_public_subset_does_not_claim_administrative_coverage(self):
        for endpoint in list(self.responses):
            if '/actions/' in endpoint or endpoint.endswith(('/vulnerability-alerts','/automated-security-fixes')): del self.responses[endpoint]
        self.responses[self.prefix]={k:v for k,v in self.responses[self.prefix].items() if k in ['visibility','default_branch']}
        for i in range(len(self.expected['rulesets'])):
            endpoint=self.prefix+'/rulesets/'+str(i)
            self.responses[endpoint]={k:v for k,v in self.responses[endpoint].items() if k != 'bypass_actors'}
        code, report=self.run_audit(True)
        self.assertEqual(code,0)
        self.assertEqual(report['status'],'passed-public-subset')
        self.assertIn('dependabot-alerts',report['notChecked'])
        self.assertEqual(self.run_audit()[0],1)

    def test_missing_ruleset_and_additional_bypass_fail(self):
        self.responses[self.prefix+'/rulesets/0']=dict(self.expected['rulesets'][0],bypass_actors=[{'actor_id':1}])
        self.assertEqual(self.run_audit()[0],1)
        self.responses[self.prefix+'/rulesets?per_page=100']=[]
        self.assertEqual(self.run_audit(True)[0],1)

if __name__ == '__main__':
    unittest.main()
