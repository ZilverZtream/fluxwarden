// Oracle: audit F07 and D29: recovery failures must be visible by node; failure
// to persist an alert is still a failure. This exercises the actual CLI main,
// collector, workflow, reconciler and SQLite with injected public transports.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Writable } from 'node:stream';
import { afterEach, expect, it } from 'vitest';
import { main } from '../../src/cli/main.js';
import { createOutput } from '../../src/output/index.js';
import type { FakeServer } from '../fakes/https.js';
import { getInfo, invoice, payment } from '../fakes/lnd/responses.js';
import { NODE_PUBKEY, loadPersistence, scratchDb, seedBase } from '../helpers/cp028-executor.js';
import { exec, seedExecution } from '../helpers/cp030-execution.js';
import { lndNode, nodeCert, writeConfig, writePolicy } from '../helpers/cp016-cli.js';
import { publishSentinel, sentinelRoot } from '../helpers/output.js';
import { prepareMoneySafetyAlertKey, registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';
import { declareFixturePaths } from '../helpers/capture-fixture.js';

const servers: FakeServer[] = [];
const beforeCredentialWrite = (path: string): void => { declareFixturePaths([path]); };
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

function capture() {
  const lines: { stream: string; text: string }[] = [];
  const transport = (stream: string) => new Writable({ write(chunk: Buffer, _encoding, done) { lines.push({ stream, text: chunk.toString('utf8') }); done(); } });
  const rendered = createOutput({ stdout: transport('stdout'), stderr: transport('stderr'), secrets: [] });
  return { lines, rendered, output: {
    write: (stream: 'stdout' | 'stderr', text: string) => { lines.push({ stream, text }); },
    wrote: (stream: 'stdout' | 'stderr') => lines.some(line => line.stream === stream),
  } };
}

for (const scenario of [4, 7, 8, 9, 'alert-write-failure'] as const) {
  it(`CP-044/F07 actual daemon reports node-specific recovery failure ${String(scenario)}`, async () => {
    const code = scenario === 'alert-write-failure' ? 8 : scenario;
    const p = await loadPersistence(), database = scratchDb('cp044-daemon'), base = seedBase(p, database);
    const dir = dirname(database), alerts = join(dir, 'alerts');
    await prepareMoneySafetyAlertKey(database);
    const hash = randomBytes(32).toString('hex'), wrongPreimage = randomBytes(32);
    publishSentinel(sentinelRoot(), `cp044-preimage-${randomUUID()}.bin`, wrongPreimage);
    // A mismatching preimage proves an invariant breach without moving money.
    expect(createHash('sha256').update(wrongPreimage).digest('hex') === hash).toBe(false);
    if (code === 7 || code === 8) {
      const seeded = seedExecution(base, { status: 'UNKNOWN', paymentHash: hash, submittedAgoMs: 300_000 });
      // Complete the public stored proposal document required by the real
      // reconciliation evidence exporter (SPEC 7.5 explanation tree).
      exec(database, 'UPDATE liquidity_proposals SET reason_json = ? WHERE id = ?',
        JSON.stringify({ inputs: [], candidates: [], exempt_fee_msat: '5000' }), seeded.approval.proposalId);
    }
    let phase: 'control' | 'daemon' = 'control', infos = 0, recovering = true;
    let stop: () => void = () => undefined;
    let alertFaultInjected = false;
    const node = await lndNode(dir, servers, { info: getInfo({ pubkey: NODE_PUBKEY }), beforeCredentialWrite, routes: {
      'GET /v1/getinfo': (ctx, fake) => {
        if (phase === 'daemon') {
          infos += 1;
          recovering = infos === 3;
          // First collection and planning each handshake. The third handshake
          // starts actual recovery. The next collection is a deterministic
          // completion barrier: it proves recovery returned before we stop.
          if (infos >= 4) stop();
          if (scenario === 'alert-write-failure' && infos === 3) {
            renameSync(alerts, join(dir, 'retained-alerts'));
            writeFileSync(alerts, 'synthetic unavailable alert directory', { mode: 0o600, flag: 'wx' });
            alertFaultInjected = true;
          }
        }
        if (code === 4 && recovering) fake.grpcError(ctx, 'grpc-error', 14, 'synthetic node unavailable');
        else fake.answer(ctx, 'getinfo', getInfo({ pubkey: NODE_PUBKEY }));
      },
      // Source: lnrpc/lightning.proto Payment/ListPaymentsResponse at pinned
      // v0.21.4-beta, already scripted by fake-lnd listpayments/grpc-error.
      'GET /v1/payments': (ctx, fake) => {
        if (code === 9 && recovering) { fake.grpcError(ctx, 'grpc-error', 14, 'synthetic payment history unavailable'); return; }
        const entries = code === 7 || code === 8 ? [payment({ payment_hash: hash, status: code === 8 ? 'SUCCEEDED' : 'IN_FLIGHT',
          payment_preimage: code === 8 ? wrongPreimage.toString('hex') : '', fee_msat: '0', fee: '0', fee_sat: '0' })] : [];
        fake.answer(ctx, 'listpayments', { payments: entries, first_index_offset: '0', last_index_offset: '1', total_num_payments: String(entries.length) });
      },
      'GET /v1/invoice/{r_hash_str}': (ctx, fake) => { fake.answer(ctx, 'lookupinvoice', invoice({ r_hash: Buffer.from(hash, 'hex').toString('base64'), state: 'OPEN' })); },
    } });
    registerMoneySafetyCredentials([node.macaroon]);
    const policy = writePolicy(dir, { 'lnd-r': { [base.sourceKey]: { minInbound: '0' } } });
    const config = writeConfig(dir, { database, policy, collectInterval: '1s', nodes: [
      { name: 'lnd-r', implementation: 'lnd', url: node.url, tlsCert: nodeCert(), credential: node.macaroon, expectedPubkey: NODE_PUBKEY },
    ] });
    const control = capture();
    const controlCode = await main(['--json', 'reconcile', '--node', 'lnd-r', '--config', config],
      { output: control.output, version: () => '1.0.0', env: {}, execArgv: [] });
    expect(controlCode, 'the same real recovery command must reproduce the selected exit').toBe(code);
    phase = 'daemon'; recovering = false;
    const daemon = capture();
    const result = await main(['daemon', '--config', config], { output: daemon.output, version: () => '1.0.0', env: {}, execArgv: [],
      daemonOutput: () => daemon.rendered, onGracefulStop: callback => { stop = callback; } });
    const warnings = daemon.lines.filter(line => line.stream === 'stderr').map(line => line.text);
    // Do not mistake an unrelated planning warning or anonymous alert for a
    // recovery warning. The operator must know the affected node and exit code.
    expect.soft(warnings.some(text => /reconcil|recovery/i.test(text) && text.includes('lnd-r') && text.includes(String(code)))).toBe(true);
    expect.soft(warnings.every(text => Buffer.byteLength(text) <= 4_096)).toBe(true);
    expect.soft(result).toBe(code === 8 ? 8 : 0);
    if (scenario === 'alert-write-failure') expect(alertFaultInjected).toBe(true);
    // 4/7/9 are retried; invariant/alert persistence failures stop the safety loop.
    if (code === 8) expect(infos).toBe(3);
    else expect(infos).toBeGreaterThanOrEqual(4);
    expect(node.fake.requests.some(request => request.method === 'POST' && /invoices|route\/send|router\/send/.test(request.url))).toBe(false);
  });
}
