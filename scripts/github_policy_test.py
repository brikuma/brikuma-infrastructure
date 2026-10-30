"""Audit behavior tests use synthetic API responses and never call GitHub."""
import contextlib
import copy
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

    def run_audit(self, public=False, organization=False):
        def api(endpoint):
            value=self.responses.get(endpoint)
            if value is None: raise ValueError('Synthetic unavailable surface')
            return value
        output=io.StringIO()
        with patch.object(policy,'api',api), patch.object(sys,'argv',['policy','audit']+(['--public-only'] if public else [])+(['--organization'] if organization else [])), contextlib.redirect_stdout(output):
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

    def omit_update_parameters(self):
        endpoint = self.prefix + '/rulesets/1'
        self.responses[endpoint] = copy.deepcopy(self.responses[endpoint])
        self.responses[endpoint]['rules'][0].pop('parameters')
        self.responses[self.prefix] = dict(self.responses[self.prefix], fork=False)
        return endpoint

    def test_nonfork_omission_passes_without_mutating_inputs(self):
        self.omit_update_parameters()
        before = copy.deepcopy(self.responses)
        expected = copy.deepcopy(self.expected)
        self.assertEqual(self.run_audit()[0], 0)
        self.assertEqual(self.run_audit(True)[0], 0)
        self.assertEqual(self.responses, before)
        self.assertEqual(self.expected, expected)

    def test_omission_fails_when_nonfork_is_not_verified(self):
        for state in [True, 'missing', 'unavailable']:
            with self.subTest(state=state):
                self.setUp()
                self.omit_update_parameters()
                if state == 'unavailable':
                    del self.responses[self.prefix]
                elif state == 'missing':
                    self.responses[self.prefix].pop('fork')
                else:
                    self.responses[self.prefix]['fork'] = state
                self.assertEqual(self.run_audit()[0], 1)
                self.assertEqual(self.run_audit(True)[0], 1)

    def test_explicit_invalid_parameters_are_not_normalized(self):
        for parameters in [None, {}, {'update_allows_fetch_and_merge': True}]:
            with self.subTest(parameters=parameters):
                self.setUp()
                endpoint = self.omit_update_parameters()
                self.responses[endpoint]['rules'][0]['parameters'] = parameters
                self.assertEqual(self.run_audit()[0], 1)
                self.assertEqual(self.run_audit(True)[0], 1)

    def test_nonfork_normalization_preserves_security_comparison(self):
        for change in ['bypass-mode', 'extra-actor', 'missing-update', 'missing-check', 'other-rule-parameters']:
            with self.subTest(change=change):
                self.setUp()
                endpoint = self.omit_update_parameters()
                authority = self.responses[endpoint]
                self.responses[self.prefix + '/rulesets/0'] = copy.deepcopy(self.responses[self.prefix + '/rulesets/0'])
                integrity = self.responses[self.prefix + '/rulesets/0']
                if change == 'bypass-mode':
                    authority['bypass_actors'][0]['bypass_mode'] = 'always'
                elif change == 'extra-actor':
                    authority['bypass_actors'].append({'actor_type': 'Team', 'actor_id': 1, 'bypass_mode': 'pull_request'})
                elif change == 'missing-update':
                    authority['rules'] = []
                elif change == 'missing-check':
                    next(r for r in integrity['rules'] if r['type'] == 'required_status_checks')['parameters']['required_status_checks'].pop()
                else:
                    next(r for r in integrity['rules'] if r['type'] == 'pull_request').pop('parameters')
                self.assertEqual(self.run_audit()[0], 1)
                if change not in ['bypass-mode', 'extra-actor']:
                    self.assertEqual(self.run_audit(True)[0], 1)

    def organization_responses(self):
        expected = self.expected
        configuration = expected['organizationSecurityConfiguration']
        self.responses.update({
            'orgs/brikuma': expected['organization'],
            'orgs/brikuma/actions/permissions': expected['organizationActions'],
            'orgs/brikuma/actions/permissions/selected-actions': expected['organizationAllowedActions'],
            'orgs/brikuma/actions/permissions/workflow': expected['workflowPermissions'],
            'orgs/brikuma/code-security/configurations/' + str(configuration['id']): configuration,
            'orgs/brikuma/code-security/configurations/defaults': [{'default_for_new_repos': 'public', 'configuration': {'id': configuration['id']}}],
            'orgs/brikuma/teams/maintainers': {'id': expected['maintainersTeamId'], 'privacy': 'closed'},
            'orgs/brikuma/teams/maintainers/members?per_page=100': [{'login': 'MatteoVincenti'}],
        })

    def test_organization_rest_pass_still_reports_ui_limit(self):
        self.organization_responses()
        code, report = self.run_audit(organization=True)
        self.assertEqual(code, 1)
        self.assertEqual(report['findings'], [{'surface': 'oauth-and-token-ui-policy', 'status': 'not-verified-by-rest'}])

    def test_organization_security_drift_is_reported(self):
        self.organization_responses()
        self.responses['orgs/brikuma/actions/permissions/selected-actions'] = {'github_owned_allowed': True, 'verified_allowed': True, 'patterns_allowed': []}
        self.responses['orgs/brikuma/code-security/configurations/defaults'] = []
        code, report = self.run_audit(organization=True)
        self.assertEqual(code, 1)
        self.assertTrue({'organization-allowed-actions', 'organization-security-defaults'}.issubset({x['surface'] for x in report['findings']}))

if __name__ == '__main__':
    unittest.main()
