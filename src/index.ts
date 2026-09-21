#!/usr/bin/env node
/**
 * AgentGuard MCP server.
 *
 * Exposes AgentGuard's local spend governance and signed provenance receipts
 * as Model Context Protocol tools, so any MCP-enabled agent stack (Claude
 * Desktop/Code, Cursor, Cline, custom hosts) can gate model spend and settle
 * every decision to an Ed25519-signed, hash-chained, content-free receipt.
 *
 * Zero data plane: tools accept metadata only (model names, token counts,
 * endpoint URLs). Prompts and completions never pass through this server.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import * as ed from '@noble/ed25519';
import { HardenedStdioServerTransport } from './stdio-transport.js';
import {
  SpendGuard,
  InMemorySpendStore,
  InMemoryDecisionLogStore,
  NdjsonDecisionLogStore,
  setCostOverride,
  lockCostOverrides,
  costOverridesLocked,
  listCostOverrides,
  verifyEntry,
  verifyChain,
  computeSignerFingerprint,
  inferProvider,
  inferProviderRoute,
  inferModelIdentity,
  inferHosting,
  inferCompliance,
  AGENTGUARD_SPEND_VERSION,
  agentGuardHome,
} from '@agentguard-run/spend';

const home = () => agentGuardHome();
const keyFile = () => path.join(home(), 'mcp-signing.json');
const TENANT = tenantId(process.env.AGENTGUARD_MCP_TENANT);
const DAILY_CAP = intEnv('AGENTGUARD_MCP_DAILY_CAP_CENTS', 500);
const PER_CALL_CAP = intEnv('AGENTGUARD_MCP_PER_CALL_CAP_CENTS', 100);
// set_model_cost exists so a self-hosted model with no published price can be priced, and such a
// model legitimately costs near zero. That also makes it the one tool that can disarm every cap:
// register a model at zero and computeCallCents returns 0, so nothing ever exceeds a cap. We do not
// forbid it, because the legitimate case is real. We make it impossible to do QUIETLY: every
// override is recorded and surfaced in spend_status, and an operator can refuse overrides outright.
const COST_OVERRIDE_DISABLED = process.env.AGENTGUARD_MCP_DISABLE_COST_OVERRIDE === '1';
// Keep in step with package.json.
const MCP_SERVER_VERSION = '0.3.1';
const MAX_MODEL_CHARS = 160;
const MAX_ENDPOINT_CHARS = 2048;
const MAX_RECEIPT_JSON_CHARS = 262144;
const MAX_TOKEN_COUNT = 1_000_000_000;
const MAX_COST_CENTS_PER_KTOK = 1_000_000_000;

const modelIdSchema = z.string()
  .min(1)
  .max(MAX_MODEL_CHARS)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/, 'model must be an ASCII metadata identifier')
  .refine(isSafeModelId, 'model contains a credential, URL, or filesystem path pattern')
  .transform((value) => value.toLowerCase());

const endpointUrlSchema = z.string()
  .max(MAX_ENDPOINT_CHARS)
  .refine(isSafeEndpointUrl, 'endpoint_url must be an HTTP(S) URL without credentials or secret query parameters');

const actorIdSchema = z.string().min(1).max(160)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/, 'actor IDs must be metadata identifiers')
  .refine(isSafeModelId, 'actor ID contains a credential or path pattern');
const actorInput = {
  agent_id: actorIdSchema.optional().describe('Optional agent identifier; signed as actor.agentId on spend_decide'),
  task_id: actorIdSchema.optional().describe('Optional task identifier; signed as actor.taskId on spend_decide'),
  workflow_id: actorIdSchema.optional().describe('Optional workflow identifier; signed as actor.workflowId on spend_decide'),
};
const actorDescription = ' Optional agent_id, task_id and workflow_id accept identifiers only; spend_decide binds them into the signed actor. Read-only and cost-configuration tools accept these fields without recording a spend decision.';

const spendDecideInput = z.object({
  ...actorInput,
  model: modelIdSchema.describe('Model name, e.g. llama-3.1-8b-instruct or gpt-5-mini'),
  input_tokens: z.number().int().nonnegative().max(MAX_TOKEN_COUNT).describe('Projected input tokens'),
  output_tokens: z.number().int().nonnegative().max(MAX_TOKEN_COUNT).describe('Projected output tokens'),
  endpoint_url: endpointUrlSchema.optional().describe('Endpoint URL. Unrecognized endpoints route as self-hosted (zero retention, your jurisdiction).'),
}).strict();

const verifyReceiptInput = z.object({
  ...actorInput,
  receipt_json: z.string()
    .max(MAX_RECEIPT_JSON_CHARS)
    .refine(isJsonObject, 'receipt_json must contain one JSON object')
    .describe('The signed receipt entry as a JSON string'),
  public_key_hex: z.string().regex(/^[0-9a-fA-F]{64}$/).optional().describe('Signer public key (64 hex characters). Defaults to this server signer.'),
}).strict();

const setModelCostInput = z.object({
  ...actorInput,
  model: modelIdSchema,
  input_cents_per_ktok: z.number().nonnegative().max(MAX_COST_CENTS_PER_KTOK),
  output_cents_per_ktok: z.number().nonnegative().max(MAX_COST_CENTS_PER_KTOK),
}).strict();

const provenancePreviewInput = z.object({
  ...actorInput,
  model: modelIdSchema,
  endpoint_url: endpointUrlSchema.optional(),
}).strict();

const noInput = z.object(actorInput).strict();

function intEnv(name: string, fallback: number): number {
  const v = Number.parseInt(process.env[name] || '', 10);
  return Number.isSafeInteger(v) && v >= 0 ? v : fallback;
}

function tenantId(value: string | undefined): string {
  const raw = String(value || '').trim();
  if (!raw) return 'mcp-local';
  const safeShape = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/.test(raw);
  const sensitive = /(?:^|[._:-])(?:sk-(?:proj-|live-|test-)?|api[_-]?key|bearer|password|private[_-]?key)/i.test(raw);
  if (safeShape && !sensitive) return raw;
  const digest = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
  return `mcp-scope-${digest}`;
}

function isJsonObject(value: string): boolean {
  try {
    const parsed = JSON.parse(value);
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

function isSafeModelId(value: string): boolean {
  const lowered = value.toLowerCase();
  if (/^[a-z]:\//.test(lowered) || /^[a-z][a-z0-9+.-]*:\/\//.test(lowered)) return false;
  if (/^ag_[a-z0-9]/.test(lowered)) return false;
  if (/(^|[/:._-])sk-(?:proj-|live-|test-)?[a-z0-9]/.test(lowered)) return false;
  if (/(^|[/:._-])(?:api[_-]?key|bearer|password|private[_-]?key)(?:[/:._-]|$)/.test(lowered)) return false;
  return true;
}

function isSafeEndpointUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    if (url.username || url.password) return false;
    for (const [key, item] of url.searchParams.entries()) {
      if (/(?:api[_-]?key|token|secret|password|authorization)/i.test(key)) return false;
      if (/(?:sk-(?:proj-|live-|test-)?[a-z0-9]|ag_[a-z0-9])/i.test(item)) return false;
    }
    return Boolean(url.hostname);
  } catch {
    return false;
  }
}

function providerRouteFor(model: string, endpointUrl?: string): string {
  const url = endpointUrl || 'http://localhost:8000/v1/chat/completions';
  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return 'self-hosted';
  }
  if (!isKnownProviderHost(hostname)) return 'self-hosted';
  return inferProviderRoute({ model, url, provider: inferProvider(model) });
}

function isKnownProviderHost(hostname: string): boolean {
  const onDomain = (domain: string) => hostname === domain || hostname.endsWith(`.${domain}`);
  if (onDomain('anthropic.com') || onDomain('openai.com')) return true;
  if (onDomain('openai.azure.com') || onDomain('cognitiveservices.azure.com')) return true;
  if (onDomain('amazonaws.com') && hostname.includes('bedrock')) return true;
  if (onDomain('googleapis.com') && (hostname.includes('aiplatform') || hostname.includes('vertex'))) return true;
  return [
    'fireworks.ai',
    'baseten.co',
    'together.xyz',
    'together.ai',
    'moonshot.cn',
    'moonshot.ai',
    'deepseek.com',
    'dashscope.aliyuncs.com',
    'alibaba.com',
    'alibabacloud.com',
  ].some(onDomain);
}

function provenanceFor(model: string, endpointUrl?: string) {
  const route = providerRouteFor(model, endpointUrl);
  const modelIdentity = inferModelIdentity(model, route);
  return {
    model_identity: modelIdentity,
    hosting: inferHosting(route),
    compliance: inferCompliance(route, modelIdentity),
    captured_at: new Date().toISOString(),
  };
}

async function loadOrCreateKeys(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  try {
    const parsed = JSON.parse(fs.readFileSync(keyFile(), 'utf8')) as { privateKeyHex: string };
    const privateKey = Uint8Array.from(Buffer.from(parsed.privateKeyHex, 'hex'));
    return { privateKey, publicKey: await ed.getPublicKeyAsync(privateKey) };
  } catch {
    const privateKey = new Uint8Array(crypto.randomBytes(32));
    fs.mkdirSync(home(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(keyFile(), JSON.stringify({ privateKeyHex: Buffer.from(privateKey).toString('hex') }) + '\n', { mode: 0o600 });
    return { privateKey, publicKey: await ed.getPublicKeyAsync(privateKey) };
  }
}

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

async function main() {
  // Refusing overrides has to mean no override can be installed by ANY route, not that one
  // route is closed. Clearing the map here was still not enough: the SDK auto-loads
  // cost-overrides.json at import, and a direct setCostOverride call or an OpenRouter catalog
  // sync could reprice models afterwards, all while this server reported overrides refused.
  // lockCostOverrides() discards what is loaded and latches the SDK's cost table shut at the
  // only two places that write it, so every later route fails loudly instead.
  if (COST_OVERRIDE_DISABLED) {
    const { discarded } = lockCostOverrides();
    if (discarded.length > 0) console.error('agentguard_mcp_persisted_cost_overrides_discarded');
  }

  const keys = await loadOrCreateKeys();
  const publicKeyHex = Buffer.from(keys.publicKey).toString('hex');
  const spendStore = new InMemorySpendStore();
  const logStore = process.env.AGENTGUARD_MCP_LEDGER === 'memory'
    ? new InMemoryDecisionLogStore()
    : new NdjsonDecisionLogStore(TENANT, { home: home(), publicKeyHex });
  let decisionsThisSession = 0;
  const costOverrides: Array<{ model: string; input_cents_per_ktok: number; output_cents_per_ktok: number; at: string }> = [];
  const guards = new Map<string, SpendGuard>();
  let decisionQueue = Promise.resolve();

  function guardForRoute(route: string): SpendGuard {
    const existing = guards.get(route);
    if (existing) return existing;
    const guard = new SpendGuard({
      policy: {
        id: 'mcp-default',
        name: 'AgentGuard MCP default policy',
        scope: { tenantId: TENANT },
        caps: [
          { amountCents: PER_CALL_CAP, window: 'per_call', action: 'block' },
          { amountCents: DAILY_CAP, window: 'per_day', action: 'block' },
        ],
        mode: 'enforce',
        version: 1,
        effectiveFrom: new Date(0).toISOString(),
      },
      signingKeys: keys,
      spendStore,
      logStore,
      providerRoute: route,
    });
    guards.set(route, guard);
    return guard;
  }

  async function decideForRoute<T>(route: string, callback: (guard: SpendGuard) => Promise<T>): Promise<T> {
    const previous = decisionQueue;
    let release!: () => void;
    decisionQueue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      const guard = guardForRoute(route);
      await guard.hydrate();
      return await callback(guard);
    } finally {
      release();
    }
  }

  // The smoke test checks this announced version against the package manifest.
  const server = new McpServer({ name: 'agentguard', version: MCP_SERVER_VERSION });

  server.registerTool(
    'spend_decide',
    {
      description: 'Gate a model call BEFORE it runs. Pass metadata only (model, token counts, endpoint URL), never prompt content. Returns allow/block plus an Ed25519-signed, content-free receipt with model and hosting provenance (weights origin, jurisdiction, retention). Unknown self-hosted models need set_model_cost first (fail-closed).' + actorDescription,
      inputSchema: spendDecideInput,
    },
    async ({ model, input_tokens, output_tokens, endpoint_url, agent_id, task_id, workflow_id }) => {
      try {
        const route = providerRouteFor(model, endpoint_url);
        const result = await decideForRoute(route, (guard) => guard.decide({
          provider: inferProvider(model),
          model,
          inputTokens: input_tokens,
          outputTokens: output_tokens,
          scope: { tenantId: TENANT, agentId: agent_id, taskId: task_id },
          workflowId: workflow_id,
        }));
        if (result.signed) decisionsThisSession += 1;
        return json({
          action: result.decision.action,
          reasons: result.decision.reasons,
          projected_cents: result.decision.projectedCents,
          provenance: result.decision.provenance,
          receipt: result.signed,
          verify_hint: 'Pass receipt to verify_receipt, or verify off-platform at https://agentguard.run/verify',
        });
      } catch (err) {
        return json({ action: 'block', error: err instanceof Error ? err.message : String(err) });
      }
    },
  );

  server.registerTool(
    'verify_receipt',
    {
      description: 'Independently verify an AgentGuard signed receipt. Returns valid true/false. Tampering with any signed field makes verification fail.' + actorDescription,
      inputSchema: verifyReceiptInput,
    },
    async ({ receipt_json, public_key_hex }) => {
      try {
        const entry = JSON.parse(receipt_json);
        const pub = public_key_hex ? Uint8Array.from(Buffer.from(public_key_hex, 'hex')) : keys.publicKey;
        const valid = await verifyEntry(entry, pub);
        return json({ valid });
      } catch (err) {
        return json({ valid: false, error: err instanceof Error ? err.message : String(err) });
      }
    },
  );

  server.registerTool(
    'export_receipts',
    {
      description: 'Export the tenant decision ledger, including earlier process runs, as a hash-chained array of signed receipts with a chain verification result. Memory mode exports this process only.' + actorDescription,
      inputSchema: noInput,
    },
    async () => {
      const entries = await logStore.read(0, Number.MAX_SAFE_INTEGER, computeSignerFingerprint(keys.publicKey));
      let chainValid: unknown = null;
      try {
        chainValid = await verifyChain(entries, keys.publicKey);
      } catch (err) {
        chainValid = { error: err instanceof Error ? err.message : String(err) };
      }
      return json({ count: entries.length, chain_verification: chainValid, receipts: entries, signer_public_key_hex: publicKeyHex });
    },
  );

  server.registerTool(
    'set_model_cost',
    {
      description: 'Register a cost for a model with no built-in pricing (required for self-hosted models: AgentGuard fails closed on unknown costs). Cents per 1,000 tokens.' + actorDescription,
      inputSchema: setModelCostInput,
    },
    async ({ model, input_cents_per_ktok, output_cents_per_ktok }) => {
      if (COST_OVERRIDE_DISABLED) {
        return json({
          ok: false,
          error: 'cost_override_disabled',
          detail: 'This server refuses model cost overrides (AGENTGUARD_MCP_DISABLE_COST_OVERRIDE=1). An unpriced model keeps failing closed.',
        });
      }
      setCostOverride(model, { inputCentsPerKtok: input_cents_per_ktok, outputCentsPerKtok: output_cents_per_ktok });
      costOverrides.push({ model, input_cents_per_ktok, output_cents_per_ktok, at: new Date().toISOString() });
      // Code only, never the model string: stderr is asserted content-free by the smoke test and is
      // not the audit surface. The reviewable detail goes to spend_status.
      console.error('agentguard_mcp_cost_override_registered');
      return json({
        ok: true,
        model,
        input_cents_per_ktok,
        output_cents_per_ktok,
        // A zero override means every cap passes for this model. Say so in the tool's own reply so a
        // reviewer reading the transcript sees the consequence, not just the acknowledgement.
        caps_effective: input_cents_per_ktok === 0 && output_cents_per_ktok === 0
          ? 'none: this model is now priced at zero, so no spend cap can be exceeded by it'
          : 'normal',
        recorded_in: 'spend_status.cost_overrides',
      });
    },
  );

  server.registerTool(
    'provenance_preview',
    {
      description: 'Preview the provenance AgentGuard would attest for a model and endpoint WITHOUT spending: model identity, weights origin country (China-origin families flagged), hosting jurisdiction, retention posture.' + actorDescription,
      inputSchema: provenancePreviewInput,
    },
    async ({ model, endpoint_url }) => {
      return json({
        provenance: provenanceFor(model, endpoint_url),
        note: 'registry preview, no spend recorded against your policy',
      });
    },
  );

  server.registerTool(
    'spend_status',
    {
      description: 'Show the active policy: caps, tenant, enforcement mode, decisions so far this session, and the signer identity.' + actorDescription,
      inputSchema: noInput,
    },
    async () => json({
      tenant: TENANT,
      caps: { per_call_cents: PER_CALL_CAP, per_day_cents: DAILY_CAP },
      mode: 'enforce',
      decisions_this_session: decisionsThisSession,
      signer_public_key_hex: publicKeyHex,
      signer_fingerprint: computeSignerFingerprint(keys.publicKey),
      sdk_version: AGENTGUARD_SPEND_VERSION,
      // The SDK version above is the dependency's. This is this server's own.
      mcp_server_version: MCP_SERVER_VERSION,
      cost_override_accepted: !COST_OVERRIDE_DISABLED,
      // Read from the SDK, not from this server's own env flag, so the reported state is
      // the state the cost table is actually in.
      cost_overrides_locked: costOverridesLocked(),
      // Every set_model_cost call this session, so a reviewer can see whether a cap was disarmed by
      // pricing a model at zero. Empty is the normal state.
      cost_overrides: costOverrides,
      // The EFFECTIVE override map, which includes any loaded from disk before this process
      // started. cost_overrides above covers only this session, so on its own it would report an
      // empty trail while a persisted zero-price override was actually deciding every call.
      cost_overrides_effective: listCostOverrides(),
      ledger: logStore instanceof NdjsonDecisionLogStore ? 'ndjson' : 'memory',
      config_env: ['AGENTGUARD_MCP_DAILY_CAP_CENTS', 'AGENTGUARD_MCP_PER_CALL_CAP_CENTS', 'AGENTGUARD_MCP_TENANT', 'AGENTGUARD_MCP_DISABLE_COST_OVERRIDE', 'AGENTGUARD_MCP_LEDGER', 'AGENTGUARD_ACTOR_DIGEST'],
    }),
  );

  const transport = new HardenedStdioServerTransport();
  await server.connect(transport);
}

main().catch(() => {
  console.error('agentguard_mcp_start_failed');
  process.exit(1);
});
