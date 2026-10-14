/*
Interface: src/commands/lab.ts exports:
  labWorkload(io: Io, options: { type: 'checkout'; count: number }, deps: { lab: LabPort }): Promise<number>
  labChaos(io: Io, options: { caseId: string }, deps: { lab: LabPort; faults: FaultPort }): Promise<number>
Io is src/commands/report.ts. LabPort is an ordinary disposable regtest lab driver:
  status(): Promise<{ up: boolean; network: string }>
  channel2ReceivableMsat(): Promise<bigint>
  checkout({merchant:'cln-m',payer:'lnd-p'|'cln-p',channels:readonly number[],amountMsat:bigint}):
    Promise<{ status:'SUCCEEDED'|'FAILED'; reason:string|null }>
  scenario(caseId:string): Promise<{ exit:number; status:string; paymentHash:string; sendCount:number }>
FaultPort: apply(caseId:string): Promise<void>; clear(caseId:string): Promise<void>.
Checkout alternates LND-P 1→2 and CLN-P 4→5 at 10,000,000 msat per invoice. Count counts all invoices.
Output result: {type,attempted,successes,failures,rejections:[{payer,reason}],
  channel2:{beforeReceivableMsat:string,afterReceivableMsat:string}}.
Named T-05 returns its observed UNKNOWN/exit7 (SPEC §14.1); a passed generic scenario may exit0 (§10.3).
Chaos output result: {caseId,status,paymentHash,sendCount}; no credential or preimage fields.
Lab availability exits2; observed network other than regtest exits5/network-lock before checkout or fault injection.
*/
import { expect, it } from 'vitest';
import { loadSrc } from '../helpers/load-src.js';
import { singleJsonDocument, runCli } from '../helpers/cli.js';
import type { Io } from '../../src/commands/report.js';

interface Checkout { readonly merchant: 'cln-m'; readonly payer: 'lnd-p' | 'cln-p'; readonly channels: readonly number[]; readonly amountMsat: bigint }
interface LabPort {
  status(): Promise<{ up: boolean; network: string }>;
  channel2ReceivableMsat(): Promise<bigint>;
  checkout(request: Checkout): Promise<{ status: 'SUCCEEDED' | 'FAILED'; reason: string | null }>;
  scenario(caseId: string): Promise<{ exit: number; status: string; paymentHash: string; sendCount: number }>;
}
interface FaultPort { apply(caseId: string): Promise<void>; clear(caseId: string): Promise<void> }
interface Module {
  labWorkload(io: Io, options: { type: 'checkout'; count: number }, deps: { lab: LabPort }): Promise<number>;
  labChaos(io: Io, options: { caseId: string }, deps: { lab: LabPort; faults: FaultPort }): Promise<number>;
}
function capture() {
  let stdout = '', stderr = '';
  const io: Io = { json: true, output: { write: (stream, text) => { if (stream === 'stdout') stdout += text; else stderr += text; }, wrote: () => stdout.length + stderr.length > 0 } };
  return { io, text: () => stdout, stderr: () => stderr };
}
function fakeLab(network = 'regtest', up = true) {
  let inbound = 25_000_000n;
  const calls: Checkout[] = [], events: string[] = [];
  const lab: LabPort = {
    status: () => Promise.resolve({ up, network }), channel2ReceivableMsat: () => Promise.resolve(inbound),
    checkout: request => {
      calls.push(request);
      if (request.payer === 'lnd-p') {
        if (inbound < request.amountMsat) return Promise.resolve({ status: 'FAILED', reason: 'INSUFFICIENT_INBOUND' });
        inbound -= request.amountMsat;
      }
      return Promise.resolve({ status: 'SUCCEEDED', reason: null });
    },
    scenario: caseId => { events.push(`scenario:${caseId}`); return Promise.resolve({ exit: 7, status: 'UNKNOWN', paymentHash: 'ab'.repeat(32), sendCount: 1 }); },
  };
  const faults: FaultPort = { apply: caseId => { events.push(`apply:${caseId}`); return Promise.resolve(); }, clear: caseId => { events.push(`clear:${caseId}`); return Promise.resolve(); } };
  return { lab, faults, calls, events, inbound: () => inbound };
}

it('CP-043/B1 checkout consumes channel 2 inbound and reports rejected invoices while exiting zero', async () => {
  const m = await loadSrc<Module>('commands/lab.ts'), f = fakeLab(), c = capture();
  expect(await m.labWorkload(c.io, { type: 'checkout', count: 6 }, { lab: f.lab })).toBe(0);
  expect(f.calls).toEqual(Array.from({ length: 6 }, (_, i) => ({ merchant: 'cln-m', payer: i % 2 === 0 ? 'lnd-p' : 'cln-p', channels: i % 2 === 0 ? [1, 2] : [4, 5], amountMsat: 10_000_000n })));
  expect(f.inbound()).toBe(5_000_000n);
  expect(singleJsonDocument(c.text())['result']).toEqual({ type: 'checkout', attempted: 6, successes: 5, failures: 1,
    rejections: [{ payer: 'lnd-p', reason: 'INSUFFICIENT_INBOUND' }], channel2: { beforeReceivableMsat: '25000000', afterReceivableMsat: '5000000' } });
  expect(c.stderr()).toBe('');
});

for (const [up, network, exit] of [[false, 'regtest', 2], [true, 'mainnet', 5]] as const) {
  it(`CP-043/B1 unavailable or non-regtest workload refuses (${String(up)}, ${network}) before paying`, async () => {
    const m = await loadSrc<Module>('commands/lab.ts'), f = fakeLab(network, up), c = capture();
    expect(await m.labWorkload(c.io, { type: 'checkout', count: 6 }, { lab: f.lab })).toBe(exit);
    expect(f.calls).toEqual([]); expect(singleJsonDocument(c.text())['error']).toMatchObject({ code: exit });
  });
}

it('CP-043/B1 public workload syntax accepts checkout and fails closed when no lab is up', async () => {
  const c = await runCli(['lab', 'workload', '--type', 'checkout', '--count', '6', '--json']);
  expect(c.status).toBe(2); expect(singleJsonDocument(c.stdout)['error']).toMatchObject({ code: 2, step: 'lab-not-up' });
});

it('CP-043/B2 named T-05 applies once, reports UNKNOWN/exit7 and clears after the one-send scenario', async () => {
  const m = await loadSrc<Module>('commands/lab.ts'), f = fakeLab(), c = capture();
  expect(await m.labChaos(c.io, { caseId: 'T-05' }, { lab: f.lab, faults: f.faults })).toBe(7);
  expect(f.events).toEqual(['apply:T-05', 'scenario:T-05', 'clear:T-05']);
  expect(singleJsonDocument(c.text())['result']).toEqual({ caseId: 'T-05', status: 'UNKNOWN', paymentHash: 'ab'.repeat(32), sendCount: 1 });
});

it('CP-043/B2 a two-send T-05 observation refuses after exactly one cleanup and emits one safe error envelope', async () => {
  const m = await loadSrc<Module>('commands/lab.ts'), f = fakeLab(), c = capture();
  f.lab.scenario = id => { f.events.push(`scenario:${id}`); return Promise.resolve({ exit: 7, status: 'UNKNOWN', paymentHash: 'ab'.repeat(32), sendCount: 2 }); };
  expect(await m.labChaos(c.io, { caseId: 'T-05' }, { lab: f.lab, faults: f.faults })).toBe(8);
  expect(f.events).toEqual(['apply:T-05', 'scenario:T-05', 'clear:T-05']);
  expect(singleJsonDocument(c.text())).toEqual({ schema: 1, command: 'lab chaos', ok: false, warnings: [], result: null,
    error: { code: 8, step: 'chaos', message: 'the fault injection, observation or cleanup failed' } });
  expect(c.stderr()).toBe('');
  expect(c.text()).not.toContain('ab'.repeat(32));
});

for (const stage of ['apply', 'scenario'] as const) {
  it(`CP-043/B2 a ${stage} exception still clears the named fault and exits8`, async () => {
    const m = await loadSrc<Module>('commands/lab.ts'), f = fakeLab(), c = capture();
    if (stage === 'apply') f.faults.apply = id => { f.events.push(`apply:${id}`); return Promise.reject(new Error('injection interrupted')); };
    else f.lab.scenario = id => { f.events.push(`scenario:${id}`); return Promise.reject(new Error('execution interrupted')); };
    expect(await m.labChaos(c.io, { caseId: 'T-05' }, { lab: f.lab, faults: f.faults })).toBe(8);
    expect(f.events).toEqual(stage === 'apply' ? ['apply:T-05', 'clear:T-05'] : ['apply:T-05', 'scenario:T-05', 'clear:T-05']);
    expect(singleJsonDocument(c.text())['error']).toMatchObject({ code: 8 });
  });
}

it('CP-043/B2 a cleanup failure cannot report a successful scenario', async () => {
  const m = await loadSrc<Module>('commands/lab.ts'), f = fakeLab(), c = capture();
  f.faults.clear = id => { f.events.push(`clear:${id}`); return Promise.reject(new Error('toxic remains')); };
  expect(await m.labChaos(c.io, { caseId: 'T-05' }, { lab: f.lab, faults: f.faults })).toBe(8);
  expect(f.events).toEqual(['apply:T-05', 'scenario:T-05', 'clear:T-05']);
});

it('CP-043/B2 public --case syntax accepts T-05 and reports the unavailable lab', async () => {
  const c = await runCli(['lab', 'chaos', '--case', 'T-05', '--json']);
  expect(c.status).toBe(2); expect(singleJsonDocument(c.stdout)['error']).toMatchObject({ code: 2, step: 'lab-not-up' });
});
