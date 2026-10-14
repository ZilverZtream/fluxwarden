// Golden authorization boundary for Core Lightning v26.06.9, commit
// a2176589f235b63bc1a37e69362dfd6c925397e9: lightningd/runes.c L78–150,
// L894–984; plugins/rest-plugin/src/shared.rs L31–58.
// rate=600 requires 60 seconds / 600 = 100 ms between successful authorizations.
// The last-used timestamp changes BEFORE the target RPC executes, even if it fails.
import { performance } from 'node:perf_hooks';
import type { ServerResponse } from 'node:http';
import { startHttpsFake, type FakeServer } from '../https.js';

export interface Authorization {
  readonly method: string;
  readonly atMs: number;
  readonly accepted: boolean;
  readonly reason: 'accepted' | 'too-soon' | 'auth';
}
export interface RpcExecution {
  readonly method: string;
  readonly params: Record<string, unknown>;
  readonly response: ServerResponse;
}
export interface CadenceServer extends FakeServer {
  readonly authorizations: Authorization[];
  readonly executions: RpcExecution[];
}
export const MIN_INTERVAL_MS = 100;

export async function startCadenceServer(options: {
  rune: string;
  execute: (rpc: RpcExecution) => void;
  authRefusal?: string;
}): Promise<CadenceServer> {
  const authorizations: Authorization[] = [];
  const executions: RpcExecution[] = [];
  let lastUsed: number | undefined;
  const fake = await startHttpsFake((request, response) => {
    const method = request.url.slice('/v1/'.length);
    const atMs = performance.now();
    const refuse = (reason: 'too-soon' | 'auth', message: string): void => {
      authorizations.push({ method, atMs, accepted: false, reason });
      response.writeHead(401, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ code: 1502, message, data: null }));
    };
    if (request.headers['rune'] !== options.rune || options.authRefusal !== undefined) {
      refuse('auth', options.authRefusal ?? 'Rune is not valid');
      return;
    }
    if (lastUsed !== undefined && atMs - lastUsed < MIN_INTERVAL_MS) {
      refuse('too-soon', 'Not permitted: rate: too soon');
      return;
    }
    // Reject before parsing parameters or invoking the money/read RPC handler.
    // startHttpsFake has collected the wire body; that body is not executed here.
    lastUsed = atMs;
    authorizations.push({ method, atMs, accepted: true, reason: 'accepted' });
    const params: unknown = JSON.parse(request.body);
    if (params === null || typeof params !== 'object' || Array.isArray(params)) throw new Error('RPC parameters must be an object');
    const rpc = { method, params: params as Record<string, unknown>, response };
    executions.push(rpc);
    options.execute(rpc);
  });
  return { ...fake, authorizations, executions };
}

export function result(response: ServerResponse, body: unknown): void {
  response.writeHead(201, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}
