import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (file) => fs.readFileSync(new URL(file, root), 'utf8');
const pkg = JSON.parse(read('package.json'));
const server = JSON.parse(read('server.json'));
const lock = JSON.parse(read('package-lock.json'));

test('registry identity, runtime and versions match the npm package', () => {
  assert.equal(server.$schema, 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json');
  assert.equal(server.name, 'io.github.MerchantGuard/agentguard');
  assert.equal(server.name, pkg.mcpName);
  assert.equal(server.title, 'AgentGuard');
  assert.equal(server.version, pkg.version);
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  assert.equal(read('src/index.ts').match(/MCP_SERVER_VERSION = '([^']+)'/)[1], pkg.version);
  assert.equal(server.packages.length, 1);
  const entry = server.packages[0];
  assert.equal(entry.registryType, 'npm');
  assert.equal(entry.identifier, pkg.name);
  assert.equal(entry.version, pkg.version);
  assert.equal(entry.runtimeHint, 'npx');
  assert.deepEqual(entry.transport, { type: 'stdio' });
  assert.equal(server.websiteUrl, 'https://agentguard.run');
  assert.equal(server.repository.url, 'https://github.com/MerchantGuard/agentguard-mcp');
  assert.equal(pkg.repository.url, `git+${server.repository.url}.git`);
  assert.ok(pkg.files.includes('server.json'));
});

test('short description fits the registry and preserves the requested full text', () => {
  const full = "Local spend caps, kill-switch blocking and Ed25519-signed receipts for AI agent tool calls. Runs on the developer's machine. Zero data plane: prompts and tool calls never pass through this server.";
  assert.ok(server.description.length <= 100);
  assert.equal(server.description, full.split('. ')[0] + '.');
  assert.equal(server._meta['io.modelcontextprotocol.registry/publisher-provided'].description, full);
});

test('listed settings are real runtime reads and license keys are secret', () => {
  const require = createRequire(import.meta.url);
  const spendRoot = new URL('.', `file://${require.resolve('@agentguard-run/spend')}`);
  const spendFiles = ['agentguard-home.js', 'cost-table.js', 'policy.js', 'license.js', 'telemetry.js'];
  const runtime = read('src/index.ts') + spendFiles.map(file => fs.readFileSync(new URL(file, spendRoot), 'utf8')).join('\n');
  const env = server.packages[0].environmentVariables;
  assert.equal(new Set(env.map(item => item.name)).size, env.length);
  for (const item of env) {
    assert.ok(runtime.includes(item.name), `${item.name} must be read by the runtime`);
    assert.ok(item.description.length > 0);
    assert.equal(item.isRequired, false);
  }
  for (const match of read('src/index.ts').matchAll(/AGENTGUARD_MCP_[A-Z_]+/g)) {
    assert.ok(env.some(item => item.name === match[0]), `${match[0]} must be documented`);
  }
  assert.equal(env.find(item => item.name === 'AGENTGUARD_LICENSE_KEY').isSecret, true);
  assert.equal(env.find(item => item.name === 'AGENTGUARD_HOME').default, undefined);
  assert.equal(env.some(item => /OPENAI|ANTHROPIC|PRIVATE_KEY/.test(item.name)), false);
});
