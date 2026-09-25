# Infrastructure documentation

ID: INFRA-DOC-001

Owner/scope: Infrastructure child

Status: Documentation-only; application deferred

Baseline: frontend execution brief 1.1.0 / consolidated product v0.0.3, 2026-09-24.

Current ownership is limited to this scope record and repository bootstrap metadata. The [frontend](../../brikuma-frontend/README.md) owns all implemented product interaction in this assignment.

Future infrastructure work requires a separately authorized specification. Hosting, environments, deployment, storage and observability are deferred; no cloud account, provider, container stack or deployment configuration is introduced here.

The child must preserve independent versioning. The owner approved the private remote `https://github.com/MatteoVincenti/brikuma-infrastructure.git`; the main project records this component as a pinned submodule. No installed runtime hooks or passed application tests are claimed. Document-only changes require applicable local link checks, Conventional Commit syntax and read-only review; full active-repository hook policy applies when implementation tooling begins.

Related: [local README](../README.md), [instructions](../AGENTS.md), [Claude adapter](../CLAUDE.md), [global repository policy](../../docs/REPOSITORIES.md), [global quality gates](../../docs/QUALITY_GATES.md).
