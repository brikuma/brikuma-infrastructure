#!/usr/bin/env python3
"""Render or audit expected GitHub policy. This command never changes GitHub."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

def api(endpoint):
    result = subprocess.run(['gh', 'api', '-H', 'X-GitHub-Api-Version: 2026-03-10', endpoint], capture_output=True)
    if result.returncode: raise ValueError('GitHub policy surface unavailable; not verified.')
    return json.loads(result.stdout) if result.stdout.strip() else {}

def contains(actual, expected):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and contains(actual[k], v) for k,v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(any(contains(a, e) for a in actual) for e in expected)
    return actual == expected

def normalize_ruleset(actual, repository):
    """GitHub omits the inapplicable upstream-fetch flag on non-fork repositories."""
    result = copy.deepcopy(actual)
    if isinstance(repository, dict) and repository.get('fork') is False and isinstance(result, dict):
        for rule in result.get('rules', []):
            if isinstance(rule, dict) and rule.get('type') == 'update' and 'parameters' not in rule:
                rule['parameters'] = {'update_allows_fetch_and_merge': False}
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['render','audit'])
    parser.add_argument('--organization', action='store_true')
    parser.add_argument('--public-only', action='store_true', help='Audit only surfaces readable by the scheduled repository token.')
    args = parser.parse_args()
    expected = json.loads((ROOT / '.github/repository-policy.json').read_text())
    if args.mode == 'render': print(json.dumps(expected, indent=2)); return 0
    if args.organization and args.public_only: raise ValueError('Organization audit requires administrative coverage.')
    findings = []
    not_checked = []
    repo = 'brikuma/' + expected['repository']
    def check(label, endpoint, value, normalize=None):
        try:
            actual = api(endpoint)
            compared = normalize(actual) if normalize else actual
            if not contains(compared, value): findings.append({'surface':label,'status':'drift'})
            return actual
        except ValueError:
            findings.append({'surface':label,'status':'not-verified'}); return None
    settings = dict(expected['settings'])
    if args.public_only:
        settings = {key:settings[key] for key in ['visibility','default_branch']}
        not_checked.extend(['secret-scanning-and-push-protection', 'workflow-permissions',
                            'external-workflow-approval', 'dependabot-alerts', 'dependabot-security-updates',
                            'merge-settings', 'ruleset-bypass-actors'])
    else:
        check('workflow-permissions', 'repos/' + repo + '/actions/permissions/workflow', expected['workflowPermissions'])
        check('external-workflow-approval', 'repos/' + repo + '/actions/permissions/fork-pr-contributor-approval', expected['forkApproval'])
        check('dependabot-alerts', 'repos/' + repo + '/vulnerability-alerts', {})
        check('dependabot-security-updates', 'repos/' + repo + '/automated-security-fixes', {'enabled':True,'paused':False})
    repository = check('repository', 'repos/' + repo, settings)
    try:
        listed = api('repos/' + repo + '/rulesets?per_page=100')
        for required in expected['rulesets']:
            required = dict(required)
            if args.public_only: required.pop('bypass_actors', None)
            matches = [r for r in listed if r['name'] == required['name']]
            if len(matches) != 1:
                findings.append({'surface':required['name'],'status':'missing-or-ambiguous'}); continue
            check(required['name'], 'repos/' + repo + '/rulesets/' + str(matches[0]['id']), required,
                  lambda actual: normalize_ruleset(actual, repository))
    except ValueError: findings.append({'surface':'rulesets','status':'not-verified'})
    check('private-reporting', 'repos/' + repo + '/private-vulnerability-reporting', {'enabled':True})
    if args.organization:
        check('organization','orgs/brikuma',expected['organization'])
        check('organization-actions','orgs/brikuma/actions/permissions',expected['organizationActions'])
        check('maintainers','orgs/brikuma/teams/maintainers',{'id':expected['maintainersTeamId'],'privacy':'closed'})
        check('maintainer-members','orgs/brikuma/teams/maintainers/members?per_page=100',[{'login':'MatteoVincenti'}])
        # OAuth approval and PAT lifetime are UI-only policies; require separate recorded verification.
        findings.append({'surface':'oauth-and-token-ui-policy','status':'not-verified-by-rest'})
    print(json.dumps({'schemaVersion':1,'repository':expected['repository'],
                      'status':'failed' if findings else ('passed-public-subset' if args.public_only else 'passed'),'findings':findings,
                      'notChecked':not_checked,
                      'organizationCoverage':'REST subset only' if args.organization else 'not checked by repository token'}, indent=2))
    return int(bool(findings))

if __name__ == '__main__':
    try: sys.exit(main())
    except (ValueError, OSError, KeyError):
        print('{"status":"blocked","reason":"Policy input unavailable; raw details withheld."}')
        sys.exit(2)
