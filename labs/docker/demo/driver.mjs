import { closeSync, constants, fstatSync, fsyncSync, ftruncateSync, lstatSync, openSync, readFileSync, writeSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { configStage, databaseStage } from '../../../dist/commands/stages.js';
import { readBoundedText } from '../../../dist/config/config.js';
import { loadPolicy } from '../../../dist/policy/load.js';
import { parseYamlSubset } from '../../../dist/policy/yaml.js';
import { policySha256 } from '../../../dist/policy/canonical.js';
import { createRuntimeLab } from './runtime.mjs';
import { prepareStarvation } from '../../scenarios/demo/prepare.mjs';
import { checkReadablePath } from '../../../dist/persistence/paths.js';
import { proposalDocument } from '../../../dist/commands/proposal-document.js';
import { ULID } from '../../../dist/core/ulid.js';

export function validateDemoPolicy(configPath, policyPath) {
  const config = configStage(configPath);
  if (!policyPath || config.policy !== resolve(policyPath)) throw new Error('demo requires explicit FLUXWARDEN_DEMO_POLICY matching the configured disposable policy');
  checkReadablePath(config.policy);
  const identity = lstatSync(config.policy);
  if (!identity.isFile() || identity.isSymbolicLink() || identity.nlink !== 1) throw new Error('demo policy must be a regular disposable file');
  const text = readBoundedText(config.policy, 'demo policy');
  const policy = loadPolicy(text);
  if (policy.network !== 'regtest' || policy.cooldown_after_success !== 1 || policy.demand.mode !== 'targets' ||
      policy.amounts.max_principal_msat !== 100000000n || policy.fees.max_fee_msat !== 300000n ||
      policy.fees.max_fee_ppm !== 2500 || policy.routing.max_cltv_delta !== 144) throw new Error('demo policy requires explicit frozen terms before any plan');
  return { config, text, policy, identity };
}

function yaml(value, indent = '') {
  if (Array.isArray(value)) return value.map(item => `${indent}- ${JSON.stringify(item)}\n`).join('');
  return Object.entries(value).map(([key, item]) => {
    const prefix = `${indent}${JSON.stringify(key)}:`;
    if (item === null || (Array.isArray(item) && item.length === 0)) return `${prefix}\n`;
    return typeof item === 'object' ? `${prefix}\n${yaml(item, `${indent}  `)}` : `${prefix} ${JSON.stringify(item)}\n`;
  }).join('');
}

export async function prepareDemoStarvation(port, { targetReceivableMsat = 5_000_000n, maxInvoiceMsat = 100_000_000n, maxPayments = 50 } = {}) {
  let firstObservation = true;
  return await prepareStarvation({
    async identity() {
      const observed = await port.identity();
      if (observed.network === 'regtest' && (targetReceivableMsat < 0n || maxInvoiceMsat < 1n || maxInvoiceMsat > 100_000_000n ||
          !Number.isSafeInteger(maxPayments) || maxPayments < 1 || maxPayments > 50)) throw new Error('demo preparation input');
      return observed;
    },
    async channels() {
      const observed = await port.channels();
      if (firstObservation) {
        if (observed.channel5ReceivableMsat < 100_000_000n) throw new Error('demo preparation channel 5 insufficient');
        if (observed.channel2ReceivableMsat < targetReceivableMsat) throw new Error('demo preparation channel 2 below target');
        firstObservation = false;
      }
      return observed;
    },
    checkout: request => port.checkout(request),
  }, { targetReceivableMsat, maxInvoiceMsat, maxPayments });
}

// The caller explicitly selects a disposable policy. Only the observed merchant targets change.
export async function prepareDemoPhase({ phase, planPath, configPath, policyPath, signal }) {
  if (!['starvation', 'chaos'].includes(phase)) throw new Error('demo preparation phase');
  const { config, text, identity } = validateDemoPolicy(configPath, policyPath);
  const runtime = await createRuntimeLab({ planPath, configPath, signal });
  try {
    const result = await prepareDemoStarvation(runtime.preparation);
    const keys = await runtime.preparation.channelKeys();
    const root = parseYamlSubset(text);
    root.targets = { ...(root.targets ?? {}), 'cln-m': { ...(root.targets?.['cln-m'] ?? {}),
      [keys.channel2]: { ...(root.targets?.['cln-m']?.[keys.channel2] ?? {}), min_inbound_msat: result.targetInboundMsat.toString() },
      [keys.channel5]: { ...(root.targets?.['cln-m']?.[keys.channel5] ?? {}), min_inbound_msat: '0' } } };
    const next = yaml(root), policy = loadPolicy(next);
    const fresh = validateDemoPolicy(configPath, policyPath);
    if (fresh.text !== text || fresh.identity.dev !== identity.dev || fresh.identity.ino !== identity.ino) throw new Error('demo policy changed during preparation');
    // Compare the open descriptor before replacing this explicitly selected policy's contents.
    const fd = openSync(config.policy, constants.O_RDWR | (constants.O_NOFOLLOW ?? 0));
    try {
      const opened = fstatSync(fd);
      if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== identity.dev || opened.ino !== identity.ino ||
          readFileSync(fd, 'utf8') !== text) throw new Error('demo policy changed during preparation');
      const bytes = Buffer.from(next);
      let written = 0;
      while (written < bytes.length) {
        const count = writeSync(fd, bytes, written, bytes.length - written, written);
        if (count < 1) throw new Error('demo policy write failed');
        written += count;
      }
      ftruncateSync(fd, bytes.length); fsyncSync(fd);
    } finally { closeSync(fd); }
    const document = { phase, before: result.before, after: result.after, payments: result.payments,
      targetInboundMsat: result.targetInboundMsat, sourceChannel: keys.channel2, targetChannel: keys.channel5, policySha256: policySha256(policy) };
    const observed = JSON.parse(JSON.stringify(document, (_, value) => typeof value === 'bigint' ? value.toString() : value));
    runtime.preparation.record(`demo-preparation-${phase}-${randomUUID()}.json`, observed);
    return observed;
  } finally { await runtime.close(); }
}

export async function observeDemoChannels({ planPath, configPath, signal }) {
  const runtime = await createRuntimeLab({ planPath, configPath, signal });
  try {
    const observed = await runtime.preparation.identity();
    if (observed.network !== 'regtest') throw new Error('demo network lock');
    return await runtime.preparation.channelKeys();
  } finally { await runtime.close(); }
}

export function verifyDemoProposal(proposal, policyHash, channels) {
  if (proposal?.action !== 'CIRCULAR_REBALANCE' || proposal.status !== 'PROPOSED' || proposal.node !== 'cln-m' ||
      proposal.principal_msat !== '100000000' || proposal.caps?.max_fee_msat !== '300000' || proposal.caps?.max_fee_ppm !== 2500 ||
      proposal.caps?.max_cltv_delta !== 144 || proposal.policy_sha256 !== policyHash) throw new Error('demo planner eligibility or frozen terms refused');
  const route = proposal.route;
  if (!channels?.channel2 || !channels?.channel5 || proposal.source_channel !== channels.channel2 ||
      proposal.target_channel !== channels.channel5 || route?.fee_msat !== '202101' || route.fee_ppm !== 2022 ||
      route.cltv_delta !== 132 || !Array.isArray(route.hops) || route.hops.length !== 3 ||
      route.hops[0]?.channel !== channels.channel2 || route.hops[2]?.channel !== channels.channel5 ||
      route.hops[0]?.amount_msat !== '100202101' || route.hops[1]?.amount_msat !== '100101000' ||
      route.hops[2]?.amount_msat !== '100000000') throw new Error('demo observed proposal differs from pinned walkthrough');
}

export function verifyDemoStoredProposal(configPath, proposalId, policyHash, channels) {
  const config = configStage(configPath), db = databaseStage(config.database, 'read');
  try {
    if (typeof proposalId !== 'string' || !proposalId.startsWith('prop_')) throw new Error('demo proposal identifier absent');
    const stored = db.proposals.find(proposalId.slice(5));
    if (!stored) throw new Error('demo proposal absent');
    verifyDemoProposal(proposalDocument(stored, Date.now()), policyHash, channels);
  } finally { db.close(); }
}

export function verifyDemoExecution(configPath, executionId, channels) {
  const config = configStage(configPath), db = databaseStage(config.database, 'read');
  try {
    if (typeof executionId !== 'string' || !ULID.test(executionId)) throw new Error('demo execution identifier absent');
    const view = db.executions.view(executionId);
    const route = view?.routeJson === null || view?.routeJson === undefined ? null : JSON.parse(view.routeJson);
    if (view?.status !== 'VERIFIED_SUCCESS' || view.actualFeeMsat !== 202101n || view.plannedFeeMsat !== 202101n ||
        view.deltaStatus !== 'MATCH' || route?.principalMsat !== '100000000' || route.totalFeeMsat !== '202101' ||
        route.totalTimelockDelta !== 132 || route.feePpmCeil !== '2022' || route.parts !== 1 || route.sourceChannelKey !== channels?.channel2 ||
        route.targetChannelKey !== channels?.channel5 || !Array.isArray(route.hops) || route.hops.length !== 3 ||
        route.hops[0]?.channelKey !== channels?.channel2 || route.hops[2]?.channelKey !== channels?.channel5 ||
        route.hops[0]?.amountOutMsat !== '100202101' || route.hops[1]?.amountOutMsat !== '100101000' ||
        route.hops[2]?.amountOutMsat !== '100000000') throw new Error('demo observed execution differs from pinned walkthrough');
  } finally { db.close(); }
}
