import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { repoRoot } from './cli.js';
import type { ChaosClient, ProxyState, Toxic } from './chaos.js';
export interface Client extends ChaosClient { populate(proxies: unknown[]): Promise<unknown>; reset(): Promise<unknown>; version(): Promise<unknown> }
export interface ClientOptions { url: string; fetch?: typeof fetch; timeoutMs?: number; signal?: AbortSignal }
export async function client(options: ClientOptions): Promise<Client> {
  let module: { createToxiproxyClient(options: ClientOptions): Client };
  try { module = await import(pathToFileURL(join(repoRoot, 'labs/docker/toxiproxy.mjs')).href) as typeof module; }
  catch (error) {
    if ((error as { code?: string }).code === 'ERR_MODULE_NOT_FOUND') throw new Error('CP-007 public proxy controls are not implemented', { cause: error });
    throw error;
  }
  return module.createToxiproxyClient(options);
}
// Toxiproxy v2.12.0 README HTTP API / SPEC 11.4 / frozen CP-007 interface.
export const managed = [
  { name: 'lnd-r-rest', listen: '0.0.0.0:18080', upstream: 'lnd-r:8080', enabled: true },
  { name: 'cln-m-rest', listen: '0.0.0.0:13010', upstream: 'cln-m:3010', enabled: true },
];
export const toxics: Toxic[] = [
  { name: 'lag', type: 'latency', stream: 'downstream', toxicity: 1, attributes: { latency: 25, jitter: 3 } },
  { name: 'hold', type: 'timeout', stream: 'upstream', toxicity: 1, attributes: { timeout: 0 } },
  { name: 'reset', type: 'reset_peer', stream: 'downstream', toxicity: 0.5, attributes: { timeout: 10 } },
  { name: 'limit', type: 'limit_data', stream: 'downstream', toxicity: 1, attributes: { bytes: 32 } },
  { name: 'slice', type: 'slicer', stream: 'upstream', toxicity: 1, attributes: { average_size: 16, size_variation: 4, delay: 1000 } },
  { name: 'rate', type: 'bandwidth', stream: 'downstream', toxicity: 1, attributes: { rate: 64 } },
  { name: 'close', type: 'slow_close', stream: 'downstream', toxicity: 1, attributes: { delay: 25 } },
];
export function stateClient(): { client: Client; state: Record<string, ProxyState>; writes: string[]; reads: () => number } {
  const state: Record<string, ProxyState> = Object.fromEntries([...managed, { name: 'foreign', enabled: false }].map(proxy => [proxy.name, { ...proxy, toxics: [] }]));
  required(state['foreign']).toxics = [{ name: 'foreign-lag', type: 'latency', attributes: { latency: 7 } }];
  const writes: string[] = []; let reads = 0;
  const client: Client = {
    list: () => { reads++; return Promise.resolve(structuredClone(state)); },
    enable: (name, enabled = true) => { writes.push(`enable:${name}`); required(state[name]).enabled = enabled; return Promise.resolve(structuredClone(state[name])); },
    add: (name, toxic) => { writes.push(`add:${name}`); required(state[name]).toxics.push(structuredClone(toxic)); return Promise.resolve(toxic); },
    remove: (name, toxicName) => { writes.push(`remove:${name}`); required(state[name]).toxics = required(state[name]).toxics.filter(toxic => toxic.name !== toxicName); return Promise.resolve(undefined); },
    reset: () => { writes.push('reset'); for (const proxy of Object.values(state)) { proxy.enabled = true; proxy.toxics = []; } return Promise.resolve(undefined); },
    populate: () => Promise.resolve(managed), version: () => Promise.resolve({ version: '2.12.0' }),
  };
  return { client, state, writes, reads: () => reads };
}
export function barrier(): { promise: Promise<void>; open: () => void } {
  let open!: () => void;
  const promise = new Promise<void>(resolve => { open = resolve; });
  return { promise, open };
}

export function required<T>(value: T | undefined): T { if (value === undefined) throw new Error('required test observation is missing'); return value; }
