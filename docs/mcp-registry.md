# AgentGuard in the official MCP Registry

The registry name is `io.github.MerchantGuard/agentguard`. The package is
`@agentguard-run/mcp`, launched locally with `npx` over stdio. The public source
mirror is <https://github.com/MerchantGuard/agentguard-mcp>.

Local spend caps, kill-switch blocking and Ed25519-signed receipts for AI agent tool calls. Runs on the developer's machine. Zero data plane: prompts and tool calls never pass through this server.

The registry's description field allows 100 characters. `server.json` uses the
first sentence there and retains the full description under
`_meta.io.modelcontextprotocol.registry/publisher-provided.description`.

The server receives MCP metadata requests locally. Prompts, tool content and
receipts are not uploaded. A configured license uses the license and seat
service; optional activation telemetry follows consent. Set
`AGENTGUARD_NO_BEACON=1` to disable that telemetry. This is distinct from an
unconditional claim that the process never uses the network.

## Release procedure

Read the current [official publishing guide](https://modelcontextprotocol.io/registry/quickstart)
and [authentication guide](https://modelcontextprotocol.io/registry/authentication)
before each release. Registry metadata currently uses the
[2025-12-11 schema](https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json).

1. Bump `package.json`, the lockfile root version, `MCP_SERVER_VERSION` in
   `src/index.ts`, `server.json.version`, and the npm package entry's version.
   Keep `package.json.mcpName` identical to `server.json.name`.
2. Use Node.js 20.19 or newer. Run `npm ci`, `npm test`, `npm pack --dry-run`,
   `npm run scan:release`, and `npm audit`. Review all failures before publishing.
3. Copy only the files in `scripts/public-files.json` to the separate public
   checkout. Resolve and reject symlinks first. Do not copy the private Git
   history, other packages, screenshots, dependencies, local settings, keys,
   runtime ledgers or patent filing materials. Preserve the existing public
   LICENSE, including its rights reservations. Review the copy and make a
   signed MerchantGuardOps commit before pushing the public mirror.
4. Install the official `mcp-publisher` release using the guide. Verify its
   release checksum when downloading a binary. Run `mcp-publisher validate
   server.json`; this uses the registry's validation endpoint.
5. Verify `npm whoami` is `john-mg`. Publish `npm publish --access public`.
   The prepublish hook runs the package tests and scan. Confirm the new version
   and `mcpName` with `npm view @agentguard-run/mcp@0.3.1 version mcpName` (use
   the new release version next time).
6. Run `mcp-publisher login github`. MerchantGuard organization publishing
   requires an organization owner. A token login must let the registry read
   organization membership; keep credentials out of files, logs and commits.
7. Run `mcp-publisher publish server.json`. npm must be available first because
   the registry verifies the published package's `mcpName`.
8. Verify the official search response and active version:

   ```sh
   curl -fsS 'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.MerchantGuard%2Fagentguard'
   ```

   Check the exact name and release version, and
   `_meta["io.modelcontextprotocol.registry/official"].status == "active"`.
   The version endpoint is
   `https://registry.modelcontextprotocol.io/v0.1/servers/io.github.MerchantGuard%2Fagentguard/versions/0.3.1`.

Do not treat a local build, successful npm upload or registry publish response
alone as proof that the searchable listing is active. Confirm the GET response.
Registry versions are immutable; use a new version for the next release.

## Environment reference

`server.json` is the machine-readable list of optional environment settings.
It includes the five MCP-specific settings, the Spend SDK's home, pricing lock,
actor digest and licensing settings, and its consent-controlled telemetry
settings. `AGENTGUARD_LICENSE_KEY` is marked secret. No provider key or signing
key is requested by the listing.

The seven CI platform markers are inherited runtime context, not required
configuration. They only contribute a boolean to opted-in telemetry. The
`AGENTGUARD_HOME` default is resolved by the runtime; the listing does not pass a
literal tilde path to the process.

## Validation scope

The public mirror and npm package are scanned through explicit file lists.
Known rejection-test sentinels are allowed only in their exact test fixture;
real keys and private machine paths are rejected without printing their values.
Patent numbers, filing and disclosure text, docket IDs, phone numbers and
unfiled-mark indicators are blocking findings. The original LICENSE retains its
legal patent-rights reservations and its exact notice identifying an already
filed MerchantGuard mark. That narrow notice exception applies only to LICENSE;
other trademark and service-mark indicators are rejected. No additional private
mark names are guessed. Patent applications, filing documents and private
invention material are excluded.

The namespace is authenticated through an owner of the MerchantGuard GitHub
organization. This confirms publisher control of the namespace; the registry
does not independently adjudicate trademark ownership.
