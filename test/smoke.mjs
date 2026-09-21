import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { LATEST_PROTOCOL_VERSION } from '@modelcontextprotocol/sdk/types.js';
import assert from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  inferCompliance,
  inferHosting,
  inferModelIdentity,
  verifyChain,
} from '@agentguard-run/spend';

// The server version, declared range, installed package and lockfile must agree.
// Use this package's registry dependency, without requiring a monorepo sibling.
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
{
  const src = fs.readFileSync('src/index.ts', 'utf8');
  const declared = src.match(/const MCP_SERVER_VERSION = '([^']+)'/)?.[1];
  assert.equal(declared, pkg.version,
    `MCP_SERVER_VERSION ${declared} does not match package.json ${pkg.version}`);

  const range = pkg.dependencies['@agentguard-run/spend'];
  const lock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
  const locked = lock.packages?.['node_modules/@agentguard-run/spend'];
  const installed = JSON.parse(
    fs.readFileSync('node_modules/@agentguard-run/spend/package.json', 'utf8'));
  assert.equal(lock.packages?.['']?.version, pkg.version, 'lockfile root version differs from package.json');
  assert.equal(lock.packages?.['']?.dependencies?.['@agentguard-run/spend'], range,
    'lockfile Spend declaration differs from package.json');
  assert.ok(locked && !locked.link, 'Spend must be a locked registry package, not a local link');
  assert.match(locked.resolved || '', /^https:\/\/registry\.npmjs\.org\/@agentguard-run\/spend\/-\/spend-[^/]+\.tgz$/);
  assert.match(locked.integrity || '', /^sha512-/);
  assert.equal(installed.name, '@agentguard-run/spend');
  assert.equal(installed.version, locked.version,
    `installed spend ${installed.version} differs from locked spend ${locked.version}`);

  // This package uses a stable exact or caret range. Reject unsupported syntax
  // rather than silently interpreting a broader range as a compatible version.
  const requirement = /^(\^)?(\d+)\.(\d+)\.(\d+)$/.exec(range);
  const resolved = /^(\d+)\.(\d+)\.(\d+)$/.exec(installed.version);
  assert.ok(requirement && resolved, `unsupported Spend version range: ${range}`);
  const wanted = requirement.slice(2).map(Number);
  const actual = resolved.slice(1).map(Number);
  const firstDifference = actual.findIndex((part, index) => part !== wanted[index]);
  const atLeastMinimum = firstDifference < 0 || actual[firstDifference] > wanted[firstDifference];
  const boundary = wanted[0] > 0 ? 0 : wanted[1] > 0 ? 1 : 2;
  const matches = requirement[1]
    ? atLeastMinimum && actual.slice(0, boundary + 1).every((part, index) => part === wanted[index])
    : firstDifference < 0;
  assert.ok(matches, `installed spend ${installed.version} does not satisfy ${range}`);
  console.log(`version consistency: ok (exercising locked registry spend ${installed.version})`);
}

// Inherited licenses, telemetry opt-ins, caps and cost-override settings must not
// contact a real account or change these fixtures. Every child gets a fresh home.
const testEnv = {
  ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('AGENTGUARD_'))),
  AGENTGUARD_NO_BEACON: '1',
  AGENTGUARD_TELEMETRY: '0',
  AGENTGUARD_LICENSE_ENDPOINT: 'http://127.0.0.1:9',
};
assert.equal(testEnv.AGENTGUARD_LICENSE_KEY, undefined);
assert.equal(testEnv.AGENTGUARD_NO_BEACON, '1');

const ledgerHome = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-mcp-ledger-'));
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ['dist/index.js'],
  env: { ...testEnv, AGENTGUARD_HOME: ledgerHome, AGENTGUARD_MCP_TENANT: 'smoke-tenant', AGENTGUARD_MCP_LEDGER: 'ndjson', AGENTGUARD_LICENSE_ENDPOINT: 'http://127.0.0.1:9' },
  stderr: 'pipe',
});
const serverLogs = [];
transport.stderr?.on('data', chunk => serverLogs.push(String(chunk)));
const client = new Client({ name: 'smoke', version: '0.0.1' });
await client.connect(transport);
assert.equal(client.getServerVersion()?.version, pkg.version, 'running server version differs from package.json');

const tools = await client.listTools();
const names = tools.tools.map(t => t.name).sort();
console.log('tools:', names.join(', '));
assert.deepEqual(names, ['export_receipts','provenance_preview','set_model_cost','spend_decide','spend_status','verify_receipt']);
for (const tool of tools.tools) {
  for (const field of ['agent_id', 'task_id', 'workflow_id']) {
    assert.ok(tool.inputSchema.properties[field], `${tool.name} documents ${field}`);
    assert.ok(tool.description.includes(field));
  }
}

const parse = r => JSON.parse(r.content[0].text);
const assertMcpError = (result, label) => {
  assert.equal(result.isError, true, `${label}: expected a structured MCP error`);
  assert.equal(result.content?.[0]?.type, 'text', `${label}: expected text error content`);
};
const withPrototypeKey = (base) => ({
  ...base,
  ...JSON.parse('{"__proto__":{"polluted":"yes"}}'),
});

// Every schema is closed: content-bearing or otherwise unexpected fields must
// fail validation before the handler mutates spend or receipt state.
let before = parse(await client.callTool({ name: 'spend_status', arguments: {} }));
let rejected = await client.callTool({
  name: 'spend_decide',
  arguments: {
    model: 'gpt-4o',
    input_tokens: 1,
    output_tokens: 1,
    prompt: 'CONTENT_MUST_NEVER_REACH_A_TOOL_HANDLER',
  },
});
assertMcpError(rejected, 'spend_decide unexpected prompt');
let after = parse(await client.callTool({ name: 'spend_status', arguments: {} }));
assert.equal(after.decisions_this_session, before.decisions_this_session);

const invalidCalls = [
  ['spend_decide missing field', 'spend_decide', { model: 'gpt-4o', input_tokens: 1 }],
  ['spend_decide wrong type', 'spend_decide', { model: 'gpt-4o', input_tokens: '1', output_tokens: 1 }],
  ['spend_decide malformed endpoint', 'spend_decide', { model: 'gpt-4o', input_tokens: 1, output_tokens: 1, endpoint_url: 'not a URL' }],
  ['spend_decide credential endpoint', 'spend_decide', { model: 'gpt-4o', input_tokens: 1, output_tokens: 1, endpoint_url: 'https://sk-proj-secret@api.openai.com/v1' }],
  ['spend_decide oversized', 'spend_decide', { model: 'm'.repeat(4097), input_tokens: 1, output_tokens: 1 }],
  ['spend_decide prototype key', 'spend_decide', withPrototypeKey({ model: 'gpt-4o', input_tokens: 1, output_tokens: 1 })],
  ['verify_receipt malformed JSON', 'verify_receipt', { receipt_json: '{' }],
  ['verify_receipt wrong type', 'verify_receipt', { receipt_json: 42 }],
  ['verify_receipt oversized', 'verify_receipt', { receipt_json: 'x'.repeat(262145) }],
  ['verify_receipt prototype key', 'verify_receipt', withPrototypeKey({ receipt_json: '{}' })],
  ['export_receipts unexpected field', 'export_receipts', { unexpected: true }],
  ['export_receipts oversized field', 'export_receipts', { oversized: 'x'.repeat(4097) }],
  ['export_receipts prototype key', 'export_receipts', withPrototypeKey({})],
  ['set_model_cost missing field', 'set_model_cost', { model: 'local-model', input_cents_per_ktok: 1 }],
  ['set_model_cost wrong type', 'set_model_cost', { model: 'local-model', input_cents_per_ktok: '1', output_cents_per_ktok: 1 }],
  ['set_model_cost oversized', 'set_model_cost', { model: 'm'.repeat(4097), input_cents_per_ktok: 1, output_cents_per_ktok: 1 }],
  ['set_model_cost prototype key', 'set_model_cost', withPrototypeKey({ model: 'local-model', input_cents_per_ktok: 1, output_cents_per_ktok: 1 })],
  ['provenance_preview missing field', 'provenance_preview', {}],
  ['provenance_preview wrong type', 'provenance_preview', { model: false }],
  ['provenance_preview non-HTTP endpoint', 'provenance_preview', { model: 'gpt-4o', endpoint_url: 'file:///Users/private/model' }],
  ['provenance_preview secret query', 'provenance_preview', { model: 'gpt-4o', endpoint_url: 'https://api.openai.com/v1?api_key=sk-proj-secret' }],
  ['provenance_preview oversized', 'provenance_preview', { model: 'm'.repeat(4097) }],
  ['provenance_preview prototype key', 'provenance_preview', withPrototypeKey({ model: 'gpt-4o' })],
  ['spend_status unexpected field', 'spend_status', { unexpected: 1 }],
  ['spend_status oversized field', 'spend_status', { oversized: 'x'.repeat(4097) }],
  ['spend_status prototype key', 'spend_status', withPrototypeKey({})],
];
before = parse(await client.callTool({ name: 'spend_status', arguments: {} }));
for (const [label, name, arguments_] of invalidCalls) {
  rejected = await client.callTool({ name, arguments: arguments_ });
  assertMcpError(rejected, label);
}
after = parse(await client.callTool({ name: 'spend_status', arguments: {} }));
assert.equal(after.decisions_this_session, before.decisions_this_session);

const promptSentinel = 'PROMPT_SENTINEL explain private payroll records';
const apiKeySentinel = 'sk-proj-MCP_SECRET_SENTINEL_7042';
const outsidePathSentinel = '/Users/private-customer/Documents/secret-model.gguf';
const sensitiveValues = [promptSentinel, apiKeySentinel, outsidePathSentinel];
const assertContentFree = (value, label) => {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  for (const sensitive of sensitiveValues) {
    assert.equal(serialized.includes(sensitive), false, `${label}: exposed ${sensitive}`);
  }
};

for (const [label, name, arguments_] of [
  ['prompt as model', 'spend_decide', { model: promptSentinel, input_tokens: 1, output_tokens: 1 }],
  ['API key as model', 'set_model_cost', { model: apiKeySentinel, input_cents_per_ktok: 1, output_cents_per_ktok: 1 }],
  ['filesystem path as model', 'provenance_preview', { model: outsidePathSentinel }],
  ['prompt as actor', 'spend_decide', { model: 'gpt-4o', input_tokens: 1, output_tokens: 1, agent_id: promptSentinel }],
  ['API key as actor', 'spend_status', { task_id: apiKeySentinel }],
  ['filesystem path as actor', 'spend_status', { workflow_id: outsidePathSentinel }],
]) {
  rejected = await client.callTool({ name, arguments: arguments_ });
  assertMcpError(rejected, label);
  assertContentFree(rejected, label);
}

rejected = await client.callTool({
  name: 'spend_status',
  arguments: { [apiKeySentinel]: true },
});
assertMcpError(rejected, 'secret-bearing unexpected field name');
assertContentFree(rejected, 'secret-bearing unexpected field name');

rejected = await client.callTool({
  name: outsidePathSentinel,
  arguments: {},
});
assertMcpError(rejected, 'path-bearing unknown tool name');
assertContentFree(rejected, 'path-bearing unknown tool name');

let contentProbe = await client.callTool({
  name: 'verify_receipt',
  arguments: {
    receipt_json: JSON.stringify({
      prompt: promptSentinel,
      api_key: apiKeySentinel,
      source_path: outsidePathSentinel,
    }),
  },
});
assertContentFree(contentProbe, 'verify_receipt content-bearing object');

// Unknown local costs and foreign-origin weights fail closed before any model call.
let r = parse(await client.callTool({
  name: 'spend_decide',
  arguments: {
    model: 'unpriced-local-model-guardrail',
    input_tokens: 1,
    output_tokens: 1,
    endpoint_url: 'http://localhost:8000/v1',
  },
}));
assert.equal(r.action, 'block');
assert.match(r.reasons?.join(' ') || '', /unknown model|no cost data/i);

for (const model of ['deepseek-v3', 'DeEpSeEk-V3']) {
  r = parse(await client.callTool({
    name: 'spend_decide',
    arguments: { model, input_tokens: 1, output_tokens: 1, endpoint_url: 'http://localhost:8000/v1' },
  }));
  assert.equal(r.action, 'block', model);
}
rejected = await client.callTool({
  name: 'spend_decide',
  arguments: { model: 'deeрseek-v3', input_tokens: 1, output_tokens: 1, endpoint_url: 'http://localhost:8000/v1' },
});
assertMcpError(rejected, 'unicode homoglyph model');

rejected = await client.callTool({
  name: 'spend_decide',
  arguments: {
    model: 'deepseek-v3',
    input_tokens: 1,
    output_tokens: 1,
    foreign_origin_consent_receipt_id: 'ag_consent_attacker_supplied',
  },
});
assertMcpError(rejected, 'unexpected consent field');

// 1. register self-hosted model cost
r = parse(await client.callTool({ name: 'set_model_cost', arguments: { model: 'llama-3.1-8b-instruct', input_cents_per_ktok: 0.005, output_cents_per_ktok: 0.008 } }));
assert.equal(r.ok, true);

// 2. gate a call
r = parse(await client.callTool({ name: 'spend_decide', arguments: { model: 'llama-3.1-8b-instruct', input_tokens: 500, output_tokens: 100, endpoint_url: 'http://localhost:8000/v1/chat/completions', agent_id: 'smoke-agent', task_id: 'smoke-task', workflow_id: 'smoke-workflow' } }));
assert.equal(r.action, 'allow');
assert.equal(r.provenance.hosting.provider_route, 'self-hosted');
assert.equal(r.receipt.signature.length, 128);
assert.deepEqual(r.receipt.decision.actor, {
  tenantId: 'smoke-tenant', agentId: 'smoke-agent', taskId: 'smoke-task', workflowId: 'smoke-workflow', provider: 'unknown',
});
console.log('spend_decide: allow, self-hosted route, signed');
console.log('actor: tenant=smoke-tenant, agent=smoke-agent, task=smoke-task, workflow=smoke-workflow (signed)');

// 3. verify the receipt
const receiptJson = JSON.stringify(r.receipt);
let v = parse(await client.callTool({ name: 'verify_receipt', arguments: { receipt_json: receiptJson } }));
assert.equal(v.valid, true);

// 4. tamper-reject
const tampered = JSON.parse(receiptJson); tampered.decision.action = 'allow_everything';
v = parse(await client.callTool({ name: 'verify_receipt', arguments: { receipt_json: JSON.stringify(tampered) } }));
assert.equal(v.valid, false);
console.log('verify_receipt: valid=true, tampered=false');

// 5. over-cap block (per_call cap 100c)
r = parse(await client.callTool({ name: 'spend_decide', arguments: { model: 'llama-3.1-8b-instruct', input_tokens: 30000000, output_tokens: 1000000 } }));
assert.equal(r.action, 'block');
console.log('over-cap: block |', (r.reasons?.[0]||'').slice(0, 50));

// 6. provenance preview exactly mirrors the installed provider registry.
const provenanceCases = [
  ['kimi-k3', 'https://model.api.baseten.co/v1', 'kimi-k2-on-baseten'],
  ['deepseek-v3', 'https://api.deepseek.com/v1', 'deepseek-direct'],
  ['deepseek-r1', 'https://api.together.xyz/v1', 'deepseek-on-together'],
  ['gpt-4o', 'https://api.openai.com/v1', 'openai-direct'],
  ['claude-3-5-sonnet', 'https://api.anthropic.com/v1', 'anthropic-direct'],
  ['gpt-4o', 'http://localhost:11434/v1', 'self-hosted'],
  ['claude-3-5-sonnet', 'https://models.internal.example/v1', 'self-hosted'],
  ['gpt-4o', 'https://notopenai.com/v1', 'self-hosted'],
  ['claude-3-5-sonnet', 'https://anthropic.attacker.example/v1', 'self-hosted'],
];
for (const [model, endpoint_url, route] of provenanceCases) {
  r = parse(await client.callTool({ name: 'provenance_preview', arguments: { model, endpoint_url } }));
  const modelIdentity = inferModelIdentity(model, route);
  assert.deepEqual(r.provenance?.model_identity, modelIdentity, `${model} model identity`);
  assert.deepEqual(r.provenance?.hosting, inferHosting(route), `${model} hosting`);
  assert.deepEqual(r.provenance?.compliance, inferCompliance(route, modelIdentity), `${model} compliance`);
}
console.log('provenance_preview: registry parity for', provenanceCases.length, 'routes');

// 7. signed spend decisions bind the same endpoint-derived registry provenance.
r = parse(await client.callTool({
  name: 'spend_decide',
  arguments: {
    model: 'gpt-4o',
    input_tokens: 1,
    output_tokens: 1,
    endpoint_url: 'https://api.openai.com/v1',
  },
}));
let signedIdentity = inferModelIdentity('gpt-4o', 'openai-direct');
assert.deepEqual(r.provenance?.model_identity, signedIdentity);
assert.deepEqual(r.provenance?.hosting, inferHosting('openai-direct'));
assert.deepEqual(r.provenance?.compliance, inferCompliance('openai-direct', signedIdentity));
assert.deepEqual(r.receipt?.decision?.provenance, r.provenance);

const concurrentRouteCalls = await Promise.all([
  ['gpt-4o', 'https://api.openai.com/v1'],
  ['gpt-4o', 'http://localhost:11434/v1'],
  ['claude-3-5-sonnet', 'https://api.anthropic.com/v1'],
  ['claude-3-5-sonnet', 'https://models.internal.example/v1'],
  ['gpt-4o', 'https://api.openai.com/v1'],
  ['gpt-4o', 'http://localhost:11434/v1'],
].map(async ([model, endpoint_url]) => parse(await client.callTool({
  name: 'spend_decide',
  arguments: { model, input_tokens: 1, output_tokens: 1, endpoint_url },
}))));
const concurrentSequences = concurrentRouteCalls.map(item => item.receipt?.sequence);
assert.equal(concurrentSequences.every(Number.isSafeInteger), true);
assert.equal(new Set(concurrentSequences).size, concurrentSequences.length);
let concurrentExport = parse(await client.callTool({ name: 'export_receipts', arguments: {} }));
assert.equal(concurrentExport.chain_verification?.ok, true);

// 8. status + export
r = parse(await client.callTool({ name: 'spend_status', arguments: {} }));
assert.ok(r.signer_public_key_hex.length === 64);
r = parse(await client.callTool({ name: 'export_receipts', arguments: {} }));
assert.ok(r.count >= 2);
console.log('export_receipts: count', r.count, '| chain:', JSON.stringify(r.chain_verification).slice(0, 40));
const diskFile = path.join(ledgerHome, 'smoke-tenant', 'decisions.ndjson');
const diskRows = fs.readFileSync(diskFile, 'utf8').trim().split('\n').map(JSON.parse);
assert.equal(diskRows.length, r.count);
assert.deepEqual(await verifyChain(diskRows, Buffer.from(r.signer_public_key_hex, 'hex')), { ok: true });
console.log(`disk ledger: ${diskRows.length} rows written to <AGENTGUARD_HOME>/smoke-tenant/decisions.ndjson; verification={"ok":true}`);

await client.close();
assertContentFree(serverLogs.join(''), 'server stderr');

// Restart against the same ledger: export includes history and the next entry
// extends its signed chain. Spend counters remain process-local.
const restartTransport = new StdioClientTransport({ command: process.execPath, args: ['dist/index.js'],
  env: { ...testEnv, AGENTGUARD_HOME: ledgerHome, AGENTGUARD_MCP_TENANT: 'smoke-tenant', AGENTGUARD_MCP_LEDGER: 'ndjson', AGENTGUARD_LICENSE_ENDPOINT: 'http://127.0.0.1:9' }, stderr: 'pipe' });
const restartClient = new Client({ name: 'restart', version: '1.0.0' });
await restartClient.connect(restartTransport);
let restartExport = parse(await restartClient.callTool({ name: 'export_receipts', arguments: {} }));
assert.equal(restartExport.count, diskRows.length);
assert.equal(restartExport.chain_verification.ok, true);
const restartedDecision = parse(await restartClient.callTool({ name: 'spend_decide', arguments: { model: 'gpt-4o', input_tokens: 1, output_tokens: 1, endpoint_url: 'https://api.openai.com/v1', agent_id: 'restart-agent' } }));
assert.equal(restartedDecision.receipt.previousHash, diskRows.at(-1).entryHash);
restartExport = parse(await restartClient.callTool({ name: 'export_receipts', arguments: {} }));
assert.equal(restartExport.count, diskRows.length + 1);
assert.equal(restartExport.chain_verification.ok, true);
await restartClient.close();
console.log(`restart: ${restartExport.count} rows; prior chain extended and verified`);

const memoryHome = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-mcp-memory-'));
const memoryTransport = new StdioClientTransport({ command: process.execPath, args: ['dist/index.js'],
  env: { ...testEnv, AGENTGUARD_HOME: memoryHome, AGENTGUARD_MCP_TENANT: 'memory-tenant', AGENTGUARD_MCP_LEDGER: 'memory', AGENTGUARD_LICENSE_ENDPOINT: 'http://127.0.0.1:9' }, stderr: 'pipe' });
const memoryClient = new Client({ name: 'memory', version: '1.0.0' });
await memoryClient.connect(memoryTransport);
const memoryDecision = parse(await memoryClient.callTool({ name: 'spend_decide', arguments: { model: 'gpt-4o', input_tokens: 1, output_tokens: 1, endpoint_url: 'https://api.openai.com/v1' } }));
assert.ok(memoryDecision.receipt.signature);
assert.equal(fs.existsSync(path.join(memoryHome, 'memory-tenant', 'decisions.ndjson')), false);
await memoryClient.close();
fs.rmSync(memoryHome, { recursive: true, force: true });
fs.rmSync(ledgerHome, { recursive: true, force: true });
console.log('memory opt-out: signed receipt, no decision ledger on disk');

const startupTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-mcp-startup-error-'));
const blockedHome = path.join(startupTemp, 'not-a-directory');
fs.writeFileSync(blockedHome, 'block directory creation');
const failedStartup = spawnSync(process.execPath, ['dist/index.js'], {
  cwd: path.resolve('.'),
  env: {
    ...testEnv,
    AGENTGUARD_HOME: blockedHome,
    AGENTGUARD_LICENSE_ENDPOINT: 'http://127.0.0.1:9',
  },
  encoding: 'utf8',
  timeout: 5000,
});
fs.rmSync(startupTemp, { recursive: true, force: true });
assert.notEqual(failedStartup.status, 0);
assert.equal(failedStartup.stderr.includes(blockedHome), false, 'startup log exposed an external filesystem path');

const secretTenantHome = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-mcp-secret-tenant-'));
const secretTenantTransport = new StdioClientTransport({
  command: process.execPath,
  args: ['dist/index.js'],
  env: {
    ...testEnv,
    AGENTGUARD_HOME: secretTenantHome,
    AGENTGUARD_LICENSE_ENDPOINT: 'http://127.0.0.1:9',
    AGENTGUARD_MCP_TENANT: apiKeySentinel,
  },
  stderr: 'pipe',
});
let secretTenantStderr = '';
secretTenantTransport.stderr?.on('data', chunk => { secretTenantStderr += String(chunk); });
const secretTenantClient = new Client({ name: 'secret-tenant-probe', version: '1.0.0' });
await secretTenantClient.connect(secretTenantTransport);
const secretTenantStatus = await secretTenantClient.callTool({ name: 'spend_status', arguments: {} });
assertContentFree(secretTenantStatus, 'secret tenant status');
await secretTenantClient.close();
fs.rmSync(secretTenantHome, { recursive: true, force: true });
assertContentFree(secretTenantStderr, 'secret tenant stderr');

const rawHome = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-mcp-raw-frames-'));
const rawChild = spawn(process.execPath, ['dist/index.js'], {
  cwd: path.resolve('.'),
  env: {
    ...testEnv,
    AGENTGUARD_HOME: rawHome,
    AGENTGUARD_LICENSE_ENDPOINT: 'http://127.0.0.1:9',
  },
  stdio: ['pipe', 'pipe', 'pipe'],
});
let rawStdout = '';
let rawStderr = '';
const rawResponses = new Map();
rawChild.stdout.on('data', chunk => {
  rawStdout += String(chunk);
  while (rawStdout.includes('\n')) {
    const newline = rawStdout.indexOf('\n');
    const line = rawStdout.slice(0, newline);
    rawStdout = rawStdout.slice(newline + 1);
    if (!line) continue;
    const message = JSON.parse(line);
    const resolve = rawResponses.get(message.id);
    if (resolve) {
      rawResponses.delete(message.id);
      resolve(message);
    }
  }
});
rawChild.stderr.on('data', chunk => { rawStderr += String(chunk); });
const rawRequest = (message) => new Promise((resolve, reject) => {
  const timeout = setTimeout(() => {
    rawResponses.delete(message.id);
    reject(new Error(`raw MCP request ${message.id} timed out`));
  }, 5000);
  rawResponses.set(message.id, response => {
    clearTimeout(timeout);
    resolve(response);
  });
  rawChild.stdin.write(JSON.stringify(message) + '\n');
});

const malformedFrame = `{not-json ${promptSentinel} ${apiKeySentinel} ${outsidePathSentinel}}\n`;
rawChild.stdin.write(malformedFrame.repeat(200));
const initializeResponse = await rawRequest({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: LATEST_PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: 'malformed-frame-survivor', version: '1.0.0' },
  },
});
assert.equal(initializeResponse.result?.serverInfo?.name, 'agentguard');
rawChild.stdin.write(JSON.stringify({
  jsonrpc: '2.0',
  method: 'notifications/initialized',
  params: {},
}) + '\n');
const statusResponse = await rawRequest({
  jsonrpc: '2.0',
  id: 2,
  method: 'tools/call',
  params: { name: 'spend_status', arguments: {} },
});
assert.equal(statusResponse.result?.isError, undefined);
assert.equal(JSON.parse(statusResponse.result.content[0].text).tenant, 'mcp-local');
const rawExit = new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error('raw MCP child did not exit after stdin closed')), 5000);
  rawChild.once('exit', code => {
    clearTimeout(timeout);
    resolve(code);
  });
});
rawChild.stdin.end();
const rawExitCode = await rawExit;
fs.rmSync(rawHome, { recursive: true, force: true });
assert.equal(rawExitCode, 0);
assertContentFree(rawStderr, 'malformed-frame stderr');
console.log('SMOKE PASS');
