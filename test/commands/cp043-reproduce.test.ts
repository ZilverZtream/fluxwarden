/*
Interface: scripts/reproduce-demo.sh --phase <lab|starvation|plan|execute|verify|chaos>
  --config <path> --key <path> --out <path> [--proposal-id <id>] [--chaos-proposal-id <new-id>] [--run-id <id>].
Each phase executes labs/scenarios/demo/walkthrough.json's command sequence, appending --config <path> --json.
FLUXWARDEN_NODE selects the Node executable; FLUXWARDEN_BIN selects a JS CLI entry (default dist/cli/bin.js).
Proposal/run/key/out placeholders are arguments, never command interpolation. Each phase has a 180-second deadline;
the narrated seven minutes are separate phases, with no artificial sleep and no raised per-case test timeout.
T-05's expected exit7 is captured, reconciled and exported; other nonzero exits stop the phase.
docs/demo-transcript.md records the exact values and evidence files of SPEC §14.1–14.2.
Before starvation and chaos, the script uses prepareStarvation through the ordinary observed lab port.
The chaos phase plans and approves a NEW unsubmitted intent; --chaos-proposal-id may never reuse --proposal-id.
*/
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { childEnv, repoRoot, scratchDir } from '../helpers/cli.js';

interface Plan { version: number; network: string; nominalDurationSeconds: number; phaseDeadlineSeconds: number; phases: { id: string; commands: string[][] }[]; expected: Record<string, string | number>; bundleFiles: string[] }
const plan = JSON.parse(readFileSync(join(repoRoot, 'labs/scenarios/demo/walkthrough.json'), 'utf8')) as Plan;
const fake = `import { appendFileSync } from 'node:fs';
const args=process.argv.slice(2);
appendFileSync(process.env.DEMO_TEST_LOG,JSON.stringify(args)+'\\n');
if(args[0]==='lab'&&args[1]==='chaos'){
  console.log(JSON.stringify({command:'lab chaos',result:{caseId:'T-05',status:'UNKNOWN',paymentHash:'ab'.repeat(32),sendCount:1},error:{code:7,step:'OUTCOME_UNKNOWN'}}));process.exit(7);
}
if(process.env.DEMO_TEST_FAIL==='yes'){console.log(JSON.stringify({result:null,error:{code:8,step:'test-fault'}}));process.exit(8);}
console.log(JSON.stringify({result:{proposal_id:process.env.DEMO_TEST_PHASE==='chaos'?'prop_chaos_fixture':'prop_fixture',run_id:'run_fixture',status:'VERIFIED_SUCCESS'},error:null}));
`;

function runPhase(phase: string, fail = false) {
  const script = join(repoRoot, 'scripts/reproduce-demo.sh');
  expect(existsSync(script), 'reproduction script').toBe(true);
  const directory = scratchDir(`demo-${phase}`), binary = join(directory, 'fake-cli.mjs'), log = join(directory, 'calls.ndjson');
  writeFileSync(binary, fake, { mode: 0o600 }); writeFileSync(log, '', { mode: 0o600 });
  const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
  const config = join(directory, 'regtest.yaml'), key = join(directory, 'operator.key'), out = join(directory, 'bundle');
  const result = spawnSync(bash, [script, '--phase', phase, '--config', config, '--key', key, '--out', out, '--proposal-id', 'prop_fixture', '--chaos-proposal-id', 'prop_chaos_fixture', '--run-id', 'run_fixture'],
    { cwd: repoRoot, shell: false, windowsHide: true, encoding: 'utf8', timeout: 10_000, env: { ...childEnv(), FLUXWARDEN_NODE: process.execPath, FLUXWARDEN_BIN: binary, DEMO_TEST_LOG: log, DEMO_TEST_PHASE: phase, DEMO_TEST_FAIL: fail ? 'yes' : 'no' } });
  const calls = readFileSync(log, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line) as string[]);
  return { result, calls, config, key, out };
}

for (const phase of plan.phases) {
  it(`CP-043/B3 ${phase.id} executes the pinned commands and continues through expected UNKNOWN only`, () => {
    const r = runPhase(phase.id);
    expect(r.result.error).toBeUndefined(); expect(r.result.status).toBe(0);
    const values: Record<string, string> = { '$proposal': 'prop_fixture', '$chaosProposal': 'prop_chaos_fixture', '$run': 'run_fixture', '$key': r.key, '$out': r.out };
    expect(r.calls).toEqual(phase.commands.map(args => [...args.map(arg => values[arg] ?? arg), '--config', r.config, '--json']));
  });
}

it('CP-043/B3 an unexpected exit aborts the phase before a later command', () => {
  const r = runPhase('verify', true);
  expect(r.result.status).toBe(8); expect(r.calls).toEqual([['channels', '--node', 'cln-m', '--config', r.config, '--json']]);
});

it('CP-043/B3 transcript pins the route, directional deltas, one-send UNKNOWN and complete bundle inventory', () => {
  const path = join(repoRoot, 'docs/demo-transcript.md'); expect(existsSync(path)).toBe(true);
  const transcript = readFileSync(path, 'utf8');
  expect(plan.version).toBe(1); expect(plan.network).toBe('regtest'); expect(plan.nominalDurationSeconds).toBe(420); expect(plan.phaseDeadlineSeconds).toBe(180);
  expect(plan.expected).toEqual({ sourceChannel: 2, targetChannel: 5, principalMsat: '100000000', feeMsat: '202101', feePpm: '2022', cltvDelta: 132, cltvCap: 144,
    sourceLocalDeltaMsat: '-100202101', targetLocalDeltaMsat: '100000000', chaosStatus: 'UNKNOWN', chaosExit: 7, sendsForUnknownHash: 1 });
  for (const value of ['100000000', '202101', '2022', '132', '144', '-100202101', 'UNKNOWN', 'T-05']) expect(transcript.replaceAll(',', '').replaceAll('_', '')).toContain(value);
  for (const file of plan.bundleFiles) expect(transcript).toContain(file);
  expect(transcript).toMatch(/one (?:sendpay|payment|send)|exactly (?:one|1) (?:sendpay|payment|send)/i);
});
