// CP-044 expected values: accepted D29 composed-verification-seal reference,
// 2026-10-27. No production implementation/private function assertions.
import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { asRecord } from './helpers/cli.js';
import { declareFixturePaths, ownedCaptureToolArgs } from './helpers/capture-fixture.js';
import { composedFixture, events, refused, runComposed } from './helpers/composed-seal.js';

it('CP-044/COMPOSE-TRANSPORT actual descriptor writes fire the final clock and closed descriptors lose path ownership', () => {
  const f = composedFixture();
  const result = spawnSync(process.execPath, [...ownedCaptureToolArgs(['--input-type=module', '--eval', `
import fs from 'node:fs';import {join} from 'node:path';
const {jobs}=await import(${JSON.stringify(pathToFileURL(join(f.source, 'composition-transport.mjs')).href)});
fs.readFileSync(join(process.env.FLUXWARDEN_CI_CAPTURE_DIR,'receipt.json'));await jobs();
const fd=fs.openSync(join(process.env.FLUXWARDEN_RELEASE_OUTPUT,'fd-output.json'),'wx',0o600);
try{fs.writeFileSync(fd,'{}');}finally{fs.closeSync(fd);}
fs.appendFileSync(process.env.CONTROL_COMPOSITION_LOG,JSON.stringify({event:'closed-descriptor-control',elapsed:610001})+'\\n');
try{fs.writeFileSync(fd,'{}');throw new Error('closed descriptor unexpectedly writable');}catch(error){if(error.code!=='EBADF')throw error;}
const outside=fs.openSync(join(process.env.CONTROL_COMPOSITION_LOG,'..','fd-outside.json'),'wx',0o600);
try{fs.writeSync(outside,'{}');}finally{fs.closeSync(outside);}
`])], { cwd: f.source, env: { ...f.env, CONTROL_COMPOSITION: 'clock-spanning' }, windowsHide: true, timeout: 10_000 });
  expect(result.error).toBeUndefined(); expect(result.signal).toBeNull(); expect(result.status).toBe(0);
  const observed = events(f);
  expect(observed).toContain('verification-input-read'); expect(observed).toContain('provider-clock');
  expect(observed.filter(event => event === 'final-write-clock'), 'a real fd write must trigger the original final-clock event exactly once').toHaveLength(1);
  expect(observed.slice(observed.indexOf('closed-descriptor-control') + 1), 'closed/reused descriptors cannot retain stale output path ownership').not.toContain('report-write');
  const rows = readFileSync(f.transportLog, 'utf8').trim().split('\n').map(line => JSON.parse(line) as { event: string; elapsed: number });
  expect(rows.find(row => row.event === 'final-write-clock')?.elapsed).toBe(610001);
});

it('CP-044/COMPOSE-LEGACY existing CLI transport completes genuine verification and original sealing', () => {
  const f = composedFixture(), result = runComposed(f, 'ordinary', true);
  expect(result.status, 'the fake existing provider transport supports an actual successful CLI seal').toBe(0);
  expect(events(f)).toContain('provider');
  expect(readFileSync(join(f.output, 'report.json'))).toEqual(f.originalReport);
});

for (const cli of [false, true]) it(`CP-044/COMPOSE-SUCCESS ${cli ? 'CLI' : 'direct API'} genuinely verifies and seals with duplicate public verifier child unavailable`, () => {
  const f = composedFixture(), result = runComposed(f, 'deny-child', cli);
  expect(result.status, 'one owned composition succeeds without starting an independent verifier subprocess').toBe(0);
  expect(events(f)).not.toContain('public-verifier-child');
  expect(events(f)).not.toContain('subordinate-cap-raised');
  expect(events(f)).toContain('provider');
  expect(readFileSync(join(f.output, 'report.json'))).toEqual(f.originalReport);
  const receipt = asRecord(JSON.parse(readFileSync(join(f.output, 'receipt.json'), 'utf8')), 'original bounded bindings');
  expect(receipt['jobId']).toBe(4242); expect(receipt['sourceCommit']).toBe(f.sourceCommit); expect(receipt['exitCode']).toBe(0);
});

for (const [label, change] of [
  ['registered secret in original retained stream', (f: ReturnType<typeof composedFixture>) => {
    const stream = join(f.capture, 'stdout.log'); declareFixturePaths([stream]); appendFileSync(stream, f.seed.toString('hex'));
  }],
  ['changed source', (f: ReturnType<typeof composedFixture>) => { appendFileSync(join(f.source, 'src/cli/bin.ts'), '// changed source\n'); }],
  ['incomplete capture', (f: ReturnType<typeof composedFixture>) => { writeFileSync(join(f.capture, 'receipt.json'), '{}'); }],
] as const) it(`CP-044/COMPOSE-VERIFY direct API forged verified options cannot bypass ${label} refusal`, () => {
  const f = composedFixture(); change(f); const result = runComposed(f);
  refused(f, result);
  expect(events(f), 'complete verification refuses before provider/report sealing').not.toContain('provider');
  const published = Buffer.from(result.stdout + result.stderr);
  expect(published.includes(f.seed) || published.includes(f.seed.toString('hex')), 'failure exposes no registered SOURCE').toBe(false);
});

it('CP-044/COMPOSE-CLI direct CLI cannot bypass full verification of changed original retained evidence', () => {
  const f = composedFixture(); appendFileSync(join(f.capture, 'receipt.json'), ' ');
  const result = runComposed(f, 'ordinary', true); refused(f, result);
  expect(events(f)).not.toContain('provider');
});

it('CP-044/COMPOSE-STABILITY mutation at provider boundary cannot seal different report bytes than just verified', () => {
  const f = composedFixture(), result = runComposed(f, 'mutate-at-provider');
  expect(events(f), 'mutation is a real public provider transport callback').toContain('provider-mutated-report');
  expect(readFileSync(join(f.evidence, 'vitest-chaos.json')).equals(f.originalReport)).toBe(false);
  refused(f, result);
});

it('CP-044/COMPOSE-SEAL provider failure after genuine verification refuses before report output', () => {
  const f = composedFixture(), result = runComposed(f, 'provider-failure');
  expect(events(f)).toContain('provider'); refused(f, result);
});

for (const mode of ['clock-provider', 'clock-spanning']) it(`CP-044/COMPOSE-DEADLINE ${mode} enforces one monotonic 600000ms budget through final writes without resetting`, () => {
  const f = composedFixture(), result = runComposed(f, mode);
  expect(events(f)).toContain('provider');
  if (mode === 'clock-spanning') {
    expect(events(f), 'logical verification consumes 420 seconds before sealing').toContain('verification-input-read');
    expect(events(f), 'final write transport advances logical whole phase beyond 600 seconds').toContain('final-write-clock');
  } else expect(events(f)).toContain('provider-clock-expired');
  refused(f, result);
  expect(events(f), '180000ms subordinate caps remain independent').not.toContain('subordinate-cap-raised');
});
