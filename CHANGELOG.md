# Changelog

## 0.3.1 (2026-09-21)

- Add official MCP registry metadata and npm ownership verification.
- Point package metadata to the package-only public mirror.
- Make release tests work without the private monorepo and add a package release scan for credentials, private paths, patent identifiers, docket IDs, phone numbers and unfiled marks.
- Document the registry update process and actual environment settings.
- Refresh five transitive dependencies within their supported ranges; npm audit reports no vulnerabilities.

## 0.3.0 (2026-09-15)

- Use spend `^0.19.0`, resolved locally to the sibling build before registry release.
- Sign tenant, agent, task, and workflow identifiers through spend's optional actor fields. Document optional identifier parameters on every tool.
- Persist signed decision chains to the tenant NDJSON ledger by default. Restarted servers extend and export the prior chain. `AGENTGUARD_MCP_LEDGER=memory` restores process-only storage.
- Smoke-test on-disk verification, actor attribution, restart continuity, and memory mode. No runtime dependencies added.

## 0.2.6 (2026-08-31)

- Share spend's home resolver, honor `AGENTGUARD_HOME`, update the spend dependency to the 0.18 line, and assert manifest/server/installed SDK consistency (`088c123`, `f313320`).
- Correct license scope and normalize the repository URL (`088c123`, `079ba4f`).

## 0.2.5 (2026-08-30)

- Correct the version announced to MCP clients and expose the server's version alongside the spend SDK version in status (`168b8c9`).
