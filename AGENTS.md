# BRIKUMA infrastructure instructions

Read [global instructions](../AGENTS.md), [global repository policy](../docs/REPOSITORIES.md) and [local scope](docs/README.md) before changes. If parent policy is absent in a standalone checkout, record the missing context and retrieve the owner-approved version before policy changes.

This child is documentation/bootstrap metadata only for the current frontend POC. Do not add application code, APIs, databases, providers, containers, deployment or runtime dependencies. Preserve independent history. Use English Conventional Commits scoped to actual documentation. No push, history rewrite or invented remote is authorized.

Repository-local documentation/privacy hooks and the `privacy`/`docs-required-gate` CI checks are required; application runtime tooling remains deferred. Follow [privacy setup](PRIVACY.md). See [README](README.md) and [Claude adapter](CLAUDE.md).
