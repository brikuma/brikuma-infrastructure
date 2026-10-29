# Contributing

Read [instructions](AGENTS.md), [scope](docs/README.md) and [privacy setup](PRIVACY.md). This repository remains documentation-only apart from governance checks. Use English Conventional Commits scoped to `docs`, `quality`, `tooling` or `deps`, with a truthful summary.

Stage explicit paths, check the indexed documentation and privacy findings, and review the exact candidate read-only before committing. Do not bypass hooks. PRs require `privacy` and `docs-required-gate`. The owner may document self-review and merge with zero external approvals; only designated maintainers may merge. Publishing or replacing remote history requires the final authorization in the global publication policy.

Run `python3 -B scripts/docs_test.py` after changing the documentation guard. Its synthetic tests verify indexed links, anchors, instruction imports and explicit parent-link declarations.
