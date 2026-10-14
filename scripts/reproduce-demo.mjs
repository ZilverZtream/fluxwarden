import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { processOutput } from '../dist/output/index.js';
import { observeDemoChannels, prepareDemoPhase, validateDemoPolicy, verifyDemoExecution, verifyDemoProposal, verifyDemoStoredProposal } from '../labs/docker/demo/driver.mjs';
import { policySha256 } from '../dist/policy/canonical.js';

const output = processOutput();
const options = new Map();
const args = process.argv.slice(2);
let stopped = false;
let child;
let phaseController;
const stop = () => { stopped = true; phaseController?.abort(); child?.kill('SIGTERM'); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);
let code = 2;
try {
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index], value = args[index + 1];
    if (!['--phase', '--config', '--key', '--out', '--proposal-id', '--chaos-proposal-id', '--run-id'].includes(key) || !value || options.has(key)) throw new Error('arguments');
    options.set(key, value);
  }
  if (['--config', '--key', '--out'].some(key => !options.has(key))) throw new Error('arguments');
  if (options.has('--chaos-proposal-id') && options.get('--chaos-proposal-id') === options.get('--proposal-id')) throw new Error('chaos requires a new intent');
  const plan = JSON.parse(readFileSync(new URL('../labs/scenarios/demo/walkthrough.json', import.meta.url), 'utf8'));
  const phase = options.get('--phase');
  const phases = phase === undefined ? plan.phases : plan.phases.filter(item => item.id === phase);
  if (!phases.length) throw new Error('phase');
  const root = fileURLToPath(new URL('../', import.meta.url));
  const values = { '$proposal': options.get('--proposal-id'), '$chaosProposal': undefined, '$run': options.get('--run-id'), '$key': options.get('--key'), '$out': options.get('--out') };
  code = 0;
  for (const current of phases) {
    const deadline = performance.now() + plan.phaseDeadlineSeconds * 1000;
    phaseController = new AbortController();
    const phaseTimer = setTimeout(() => phaseController.abort(), plan.phaseDeadlineSeconds * 1000);
    try {
    const live = process.env.FLUXWARDEN_LAB_PLAN;
    let policyHash;
    let channels;
    if (live) {
      if (plan.preparation.beforePhases.includes(current.id)) {
        const prepared = await prepareDemoPhase({ phase: current.id, planPath: live, configPath: options.get('--config'), policyPath: process.env.FLUXWARDEN_DEMO_POLICY, signal: phaseController.signal });
        output.write('stdout', `${JSON.stringify({ command: 'demo preparation', result: prepared })}\n`);
      }
      if (current.commands.some(command => (command[0] === 'liquidity' && command[1] === 'plan') ||
          (command[0] === 'actions' && command[1] === 'execute'))) {
        policyHash = policySha256(validateDemoPolicy(options.get('--config'), process.env.FLUXWARDEN_DEMO_POLICY).policy);
      }
      if (current.commands.some(command => (command[0] === 'liquidity' && command[1] === 'plan') ||
          (command[0] === 'actions' && command[1] === 'execute'))) {
        channels = await observeDemoChannels({ planPath: live, configPath: options.get('--config'), signal: phaseController.signal });
      }
      if (current.id === 'execute') verifyDemoStoredProposal(options.get('--config'), values['$proposal'], policyHash, channels);
    }
    for (const pinned of current.commands) {
      const command = pinned.map(token => {
        if (!(token in values)) return token;
        if (!values[token]) throw new Error('missing identifier');
        return values[token];
      });
      const remaining = deadline - performance.now();
      if (remaining <= 0 || stopped) { code = stopped ? 130 : 4; break; }
      const result = await new Promise(resolveResult => {
        let stdout = '', stderr = '', settled = false;
        const complete = exit => { if (settled) return; settled = true; clearTimeout(timer); resolveResult({ exit, stdout, stderr }); };
        child = spawn(process.env.FLUXWARDEN_NODE || process.execPath, [process.env.FLUXWARDEN_BIN || resolve(root, 'dist/cli/bin.js'), ...command, '--config', options.get('--config'), '--json'], { cwd: root, shell: false, windowsHide: true });
        const timer = setTimeout(() => { child.kill('SIGTERM'); complete(4); }, remaining);
        child.stdout.on('data', chunk => { stdout += chunk; if (Buffer.byteLength(stdout) > 4 * 1024 * 1024) { child.kill('SIGTERM'); complete(8); } });
        child.stderr.on('data', chunk => { stderr += chunk; if (Buffer.byteLength(stderr) > 65536) { child.kill('SIGTERM'); complete(8); } });
        child.once('error', () => complete(2)); child.once('close', status => complete(stopped ? 130 : status ?? 8));
      });
      output.write('stdout', result.stdout); output.write('stderr', result.stderr);
      if (result.exit === 0) {
        let document;
        try { document = JSON.parse(result.stdout); } catch { code = 8; break; }
        if (command[0] === 'liquidity' && command[1] === 'plan') {
          const proposal = document.result;
          const id = proposal?.proposal_id ?? proposal?.proposals?.find(item => item.action_type === 'CIRCULAR_REBALANCE')?.proposal_id;
          if (typeof id !== 'string' || !id.startsWith('prop_')) throw new Error('planner supplied no intent');
          if (policyHash) verifyDemoProposal(proposal, policyHash, channels);
          if (current.id === 'chaos') {
            if (id === values['$proposal'] || (options.has('--chaos-proposal-id') && id !== options.get('--chaos-proposal-id'))) throw new Error('chaos requires a fresh planner intent');
            values['$chaosProposal'] = id;
          } else {
            if (values['$proposal'] && values['$proposal'] !== id) throw new Error('planner intent differs from supplied proposal');
            values['$proposal'] = id;
          }
        }
        if (live && command[0] === 'actions' && command[1] === 'execute') {
          verifyDemoExecution(options.get('--config'), document.result?.execution_id, channels);
        }
        values['$run'] = document.result?.run_id ?? values['$run'];
        continue;
      }
      if (command[0] === 'lab' && command[1] === 'chaos' && result.exit === 7) {
        const document = JSON.parse(result.stdout);
        if (document.result?.status === 'UNKNOWN' && document.result?.sendCount === 1) continue;
      }
      code = result.exit; break;
    }
    } finally { clearTimeout(phaseTimer); }
    if (code !== 0) break;
  }
} catch (error) {
  if (code === 0) code = stopped ? 130 : phaseController?.signal.aborted ? 4 : 2;
  const conflicts = ['demo observed proposal differs from pinned walkthrough', 'demo observed execution differs from pinned walkthrough'];
  output.write('stderr', conflicts.includes(error?.message)
    ? `demo: ${error.message}; inspect recorded observations before changing the walkthrough\n`
    : 'demo: prerequisites, identifiers or command observations refused\n');
}
finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
process.exitCode = code;
