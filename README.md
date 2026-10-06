# @agentguard-run/mcp

[![smithery badge](https://smithery.ai/badge/agentguard-run/agentguard)](https://smithery.ai/servers/agentguard-run/agentguard)

AgentGuard® as an MCP server: local spend caps and Ed25519-signed provenance receipts for AI agent actions, usable from any Model Context Protocol host (Claude Desktop, Claude Code, Cursor, Cline, or your own agent runtime).

**Zero data plane.** Tools accept metadata only: model names, token counts, endpoint URLs. Prompts and completions never pass through this server, and their content stays on your machine. Receipts are content-free.

A configured license uses the license and seat service. Optional activation telemetry requires consent and can be disabled with `AGENTGUARD_NO_BEACON=1`. Neither path sends prompts, tool content or receipts.

## Install

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "npx",
      "args": ["-y", "@agentguard-run/mcp"]
    }
  }
}
```

Optional environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `AGENTGUARD_MCP_DAILY_CAP_CENTS` | `500` | Hard per-day spend cap (block on exceed) |
| `AGENTGUARD_MCP_PER_CALL_CAP_CENTS` | `100` | Hard per-call spend cap (block on exceed) |
| `AGENTGUARD_MCP_TENANT` | `mcp-local` | Tenant scope stamped into receipts |
| `AGENTGUARD_HOME` | `~/.agentguard` | Signing key and decision-ledger directory |
| `AGENTGUARD_MCP_LEDGER` | `ndjson` | Persist signed decisions; `memory` restores process-only storage |
| `AGENTGUARD_MCP_DISABLE_COST_OVERRIDE` | unset | `1` discards and prevents pricing overrides |
| `AGENTGUARD_ACTOR_DIGEST` | unset | `1` stores SHA-256 digests of actor IDs; provider stays readable |

A signing keypair is generated on first run and persisted to `<AGENTGUARD_HOME>/mcp-signing.json` (0600). Signed decisions are appended to `<AGENTGUARD_HOME>/<tenant>/decisions.ndjson`, including the public verification key. Exports include prior process runs and new decisions extend the existing chain. Tenant directory names use the spend store's filename normalization. Spend counters remain process-local, as in earlier versions.

All tools accept optional `agent_id`, `task_id`, and `workflow_id` identifier parameters. `spend_decide` passes these to the call context, signing them as `actor.agentId`, `actor.taskId`, and `actor.workflowId`; the configured tenant becomes `actor.tenantId`. Other tools accept these metadata fields without recording a spend decision. Prompts, arbitrary content, credentials, and filesystem paths are rejected as IDs. Existing calls without these parameters keep working.

## Tools

- **`spend_decide`**: gate a model call before it runs. Returns allow/block plus a signed, hash-chained receipt recording model identity, weights origin country (China-origin families such as GLM, DeepSeek, Qwen, and Kimi are flagged automatically), hosting jurisdiction, and retention posture. Unrecognized endpoints (vLLM, Ollama, TGI, your own cluster) route as `self-hosted`: zero retention, your jurisdiction.
- **`verify_receipt`**: independently verify any receipt. Change one signed byte and verification fails.
- **`export_receipts`**: export the tenant decision ledger as a verified hash chain, including earlier process runs. Memory mode exports only the current process.
- **`set_model_cost`**: register pricing for self-hosted models (AgentGuard fails closed on unknown costs).
- **`provenance_preview`**: see what would be attested for a model/endpoint without spending.
- **`spend_status`**: active caps, tenant, decision count, signer fingerprint.

## Why

When agents move from hosted APIs to self-hosted models, the provider's spend dashboard, rate limits, and audit logs disappear with the provider. AgentGuard puts them back, locally, and adds something hosted providers never gave you: a cryptographic receipt an outsider can verify without trusting you or us.

More: https://agentguard.run/sovereign/ and https://agentguard.run/sovereign/guide/

## Verify independently

Any receipt can be checked off-platform at https://agentguard.run/verify or with `verify_receipt` and the signer public key from `spend_status`.

## Local release verification

Requires Node.js 20.19 or later. Run `npm ci`, `npm test`, and `npm run scan:release`
from this package or its public mirror. The lockfile uses the published spend
0.19.0 package; no private sibling checkout is required.

Release checklist: keep `package.json`, the server version in `src/index.ts`, and
both versions in `server.json` aligned; run the tests and release scan; publish
npm first, publish with `mcp-publisher`, then verify the registry's active entry.
See [the registry release guide](https://github.com/MerchantGuard/agentguard-mcp/blob/main/docs/mcp-registry.md) for exact commands and the
public mirror allowlist.

The official registry name is `io.github.MerchantGuard/agentguard`. Its package
entry runs `@agentguard-run/mcp` locally through `npx` and stdio.

AgentGuard® is a registered trademark of Dunecrest Ventures Inc. US patent filings pending. This package is governance software, not legal or compliance advice.
