import process from 'node:process';
import { JSONRPCMessageSchema, type JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

const MAX_FRAME_BYTES = 1024 * 1024;
const REJECTED_KEY_SENTINEL = 'agentguard_rejected_argument_shape';
const REJECTED_TOOL_NAME = 'agentguard_rejected_tool_name';
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const TOOL_ARGUMENT_KEYS: Record<string, Set<string>> = {
  spend_decide: new Set(['model', 'input_tokens', 'output_tokens', 'endpoint_url']),
  verify_receipt: new Set(['receipt_json', 'public_key_hex']),
  export_receipts: new Set(),
  set_model_cost: new Set(['model', 'input_cents_per_ktok', 'output_cents_per_ktok']),
  provenance_preview: new Set(['model', 'endpoint_url']),
  spend_status: new Set(),
};
for (const keys of Object.values(TOOL_ARGUMENT_KEYS)) {
  for (const key of ['agent_id', 'task_id', 'workflow_id']) keys.add(key);
}

export class HardenedStdioServerTransport implements Transport {
  private buffer = Buffer.alloc(0);
  private started = false;

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T) => void;

  private readonly onData = (chunk: Buffer) => {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.processBuffer();
  };

  private readonly onError = () => {
    this.onerror?.(new Error('stdio_input_error'));
  };

  async start(): Promise<void> {
    if (this.started) throw new Error('stdio_transport_already_started');
    this.started = true;
    process.stdin.on('data', this.onData);
    process.stdin.on('error', this.onError);
  }

  async close(): Promise<void> {
    process.stdin.off('data', this.onData);
    process.stdin.off('error', this.onError);
    if (process.stdin.listenerCount('data') === 0) process.stdin.pause();
    this.buffer = Buffer.alloc(0);
    this.onclose?.();
  }

  async send(message: JSONRPCMessage): Promise<void> {
    const serialized = JSON.stringify(message) + '\n';
    if (process.stdout.write(serialized)) return;
    await new Promise<void>((resolve) => process.stdout.once('drain', resolve));
  }

  private processBuffer(): void {
    while (true) {
      const newline = this.buffer.indexOf('\n');
      if (newline === -1) {
        if (this.buffer.length > MAX_FRAME_BYTES) {
          this.buffer = Buffer.alloc(0);
          this.onerror?.(new Error('stdio_frame_too_large'));
        }
        return;
      }

      const line = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1);
      if (line.length > MAX_FRAME_BYTES) {
        this.onerror?.(new Error('stdio_frame_too_large'));
        continue;
      }

      try {
        const parsed = JSON.parse(line.toString('utf8')) as unknown;
        sanitizeToolRequest(parsed);
        this.onmessage?.(JSONRPCMessageSchema.parse(parsed));
      } catch {
        this.onerror?.(new Error('invalid_stdio_frame'));
      }
    }
  }
}

function sanitizeToolRequest(message: unknown): void {
  if (!isRecord(message)) return;
  const params = message.params;
  if (!isRecord(params) || message.method !== 'tools/call') return;
  const toolName = typeof params.name === 'string' ? params.name : '';
  const allowedKeys = TOOL_ARGUMENT_KEYS[toolName];
  if (!allowedKeys) {
    params.name = REJECTED_TOOL_NAME;
    return;
  }
  if (!isRecord(params.arguments)) return;

  let rejected = removeDangerousKeys(params.arguments);
  for (const key of Object.keys(params.arguments)) {
    if (allowedKeys.has(key)) continue;
    delete params.arguments[key];
    rejected = true;
  }
  if (rejected) {
    Object.defineProperty(params.arguments, REJECTED_KEY_SENTINEL, {
      value: true,
      enumerable: true,
      configurable: true,
    });
  }
}

function removeDangerousKeys(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.reduce((found, item) => removeDangerousKeys(item) || found, false);
  }
  if (!isRecord(value)) return false;
  let found = false;
  for (const key of Object.keys(value)) {
    if (DANGEROUS_KEYS.has(key)) {
      delete value[key];
      found = true;
      continue;
    }
    if (removeDangerousKeys(value[key])) found = true;
  }
  return found;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
