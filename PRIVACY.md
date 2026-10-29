# Privacy checks

Use this repository's tools from its Git root. Python 3.9 or later, Git and network access for the explicit initial scanner download are required. Gitleaks is installed only under ignored `.tools/`; no global installation or download occurs inside hooks. Its archive and executable checksums are fixed in `gitleaks.lock.json`. Upstream Gitleaks 8.30.1 uses MIT; the installer retains its license.

Set `user.email` in this repository to your GitHub-assigned `noreply` address and keep your actual author name. Check Settings → Emails on GitHub: keep your email private, block pushes exposing it, and verify the address used for web commits. Do not copy another contributor's identity or change global Git configuration. The project owner uses `6958534+MatteoVincenti@users.noreply.github.com`.

```sh
python3 -B scripts/privacy-install.py
python3 -B scripts/privacy_test.py
python3 -B scripts/privacy.py full --all-objects
```

The first command verifies and installs the pinned executable. The second runs synthetic negative and clean-case tests in disposable repositories. The last checks all available refs and object versions, including removed content, raw identities, messages, tag metadata, filenames and secrets. Success is exit 0 with `status: passed`; findings return 1; incomplete input or a missing/tampered tool returns 2. A shallow clone is refused. Fetch the exact required refs before scanning; absent remote objects are not silently skipped.

Run `python3 -B scripts/install-hooks.py` to install the documentation/privacy hooks. It refuses to replace a different existing hooksPath. There are no application or npm runtime dependencies in this documentation-only repository.

Pre-commit checks the complete index and effective author/committer identities. Commit-msg checks the proposed message and trailers. Pre-push consumes every update supplied by Git and scans every introduced commit; a new branch scans its entire ancestry. An unavailable remote base blocks the push until fetched. Hooks can be bypassed by Git, so required CI and repository permissions remain necessary.

For a PR candidate, use exact hashes:

```sh
python3 -B scripts/privacy.py range --base BASE_SHA --head HEAD_SHA --integration MERGE_SHA
```

Replace the uppercase placeholders with verified objects. The base/head range includes intermediate commits; the integration commit is inspected separately. The PR workflow obtains its scanner, checksums and exception policy from the base SHA. Scanner/workflow/dependency changes additionally require local testing and documented review of the exact candidate SHA before merge. On initial bootstrap, the base must first contain the locally reviewed controls; missing approved code fails closed.

`privacy-policy.json` contains only explicit, reasoned approvals for immutable public upstream blobs. It never exempts secret findings or new commit identities. Do not add an exemption to silence an unexplained match. Reports omit matched values and replace sensitive locations with opaque identifiers. Review the underlying private object locally; never paste its raw value into an issue, PR or log.

Image pixels, embedded metadata, compressed documents, LFS payloads and GitHub-hosted content still require the manual coverage recorded in the publication audit. Public code scanning does not certify those surfaces. Never publish a report claiming uninspected data is clean.

The [publication policy](https://github.com/brikuma/brikuma/blob/main/docs/PUBLICATION.md) owns organization configuration, history cleanup, review and final authorization. The expected local GitHub configuration is `.github/repository-policy.json`; `python3 -B scripts/github-policy.py render` only prints it, and `audit` only reads actual settings. The weekly workflow uses `audit --public-only`: it checks readable repository/ruleset/reporting settings and explicitly lists administrative surfaces as not checked. Run `audit --organization` using approved owner access for secret scanning, Actions permissions, Dependabot and organization settings; OAuth/PAT policies still need UI verification. A passing public subset is not a complete organization audit.

Original project content uses the [MIT license](LICENSE). Preserve all upstream notices. Use the repository's GitHub Private Vulnerability Reporting channel once enabled; never post secrets or private data in a public issue.
