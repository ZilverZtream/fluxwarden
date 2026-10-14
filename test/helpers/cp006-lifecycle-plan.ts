import { readFileSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { asRecord } from './cli.js';
import type { Owner } from './cp006-lab.js';
import { LabInvalidError, rows } from './cp006-oracle.js';

export type Scenario =
  | { outcome: 'child-failure'; trigger: { kind: 'owned-child-exit'; service: 'lnd-p' } }
  | { outcome: 'INVALID'; trigger: { kind: 'invalid-network'; service: 'lnd-p'; network: 'mainnet' } }
  | { outcome: 'timeout'; trigger: { kind: 'deadline'; service: 'lnd-p' } }
  | { outcome: 'exception'; trigger: { kind: 'transport-exception'; service: 'lnd-p' } }
  | { outcome: 'SIGINT' | 'SIGTERM'; trigger: { kind: 'SIGINT' | 'SIGTERM' } };
export interface LiveOwner { declaration: string; owner: Owner; scenarios: Scenario[] }

function declarationRecord(path: string): Record<string, unknown> {
  try { return asRecord(JSON.parse(readFileSync(path, 'utf8')) as unknown, 'independent execution declaration'); }
  catch { throw new LabInvalidError('independent execution declaration is absent unreadable or malformed'); }
}

// Independently supplied execution input; outcomes are bound to concrete stimuli.
// No caller-supplied output pattern or retained execution report can establish a failure.
export function lifecyclePlan(input = process.env['FLUXWARDEN_LAB_RESOURCE_PLAN']): LiveOwner[] {
  if (!input || !isAbsolute(input)) throw new LabInvalidError('absolute independent live two-owner plan is required before startup');
  const raw = declarationRecord(input);
  if (raw['version'] !== 2 || raw['authorized'] !== true || raw['disposable'] !== true || raw['network'] !== 'regtest') throw new LabInvalidError('version 2 explicit disposable regtest execution authorization required');
  const declared = rows(raw['owners'], 'two explicit owners');
  if (declared.length !== 2) throw new LabInvalidError('exactly two independently authorized owners required');
  const plans = declared.map(selected => {
    const declaration = selected['declaration'];
    if (typeof declaration !== 'string' || !isAbsolute(declaration)) throw new LabInvalidError('absolute explicit owner declaration required');
    const value = declarationRecord(declaration);
    if (value['version'] !== 1 || typeof value['id'] !== 'string' || typeof value['project'] !== 'string' || !/^fluxwarden-lab-[a-z0-9-]+$/.test(value['project'])) throw new LabInvalidError('explicit isolated owner identity required');
    for (const key of ['runtimeRoot', 'tmpRoot', 'sentinelRoot', 'evidenceRoot']) if (typeof value[key] !== 'string' || !isAbsolute(value[key])) throw new LabInvalidError('absolute owner roots required');
    const ports = asRecord(value['ports'], 'owner ports'), resources = asRecord(value['resources'], 'owner resources');
    for (const key of ['lndRest', 'clnRest', 'toxiproxy']) if (typeof ports[key] !== 'number' || !Number.isInteger(ports[key]) || ports[key] < 1024 || ports[key] > 65535) throw new LabInvalidError('valid explicit owner port required');
    for (const [key, max] of [['cpus', 4], ['memoryBytes', 4294967296], ['pids', 1024]] as const) if (typeof resources[key] !== 'number' || !Number.isFinite(resources[key]) || resources[key] <= 0 || resources[key] > max) throw new LabInvalidError('bounded independent resource declaration required');
    const scenarios = rows(selected['scenarios'], 'explicit lifecycle scenarios').map((sample): Scenario => {
      if ('failurePattern' in sample) throw new LabInvalidError('output patterns cannot establish lifecycle outcomes');
      const outcome = sample['outcome'], trigger = asRecord(sample['trigger'], 'distinct owner trigger'), kind = trigger['kind'];
      if (outcome === 'SIGINT' || outcome === 'SIGTERM') {
        if (kind !== outcome) throw new LabInvalidError('signal outcome must match actual signal');
        return { outcome, trigger: { kind: outcome } };
      }
      if (trigger['service'] !== 'lnd-p') throw new LabInvalidError('failure boundary must be the explicit owned lnd-p getinfo');
      if (outcome === 'child-failure' && kind === 'owned-child-exit') return { outcome, trigger: { kind, service: 'lnd-p' } };
      if (outcome === 'INVALID' && kind === 'invalid-network' && trigger['network'] === 'mainnet') return { outcome, trigger: { kind, service: 'lnd-p', network: 'mainnet' } };
      if (outcome === 'timeout' && kind === 'deadline') return { outcome, trigger: { kind, service: 'lnd-p' } };
      if (outcome === 'exception' && kind === 'transport-exception') return { outcome, trigger: { kind, service: 'lnd-p' } };
      throw new LabInvalidError('failure outcome does not match its distinct observable trigger');
    });
    if (scenarios.length !== 6 || new Set(scenarios.map(sample => sample.outcome)).size !== 6) throw new LabInvalidError('all six distinct failure outcomes required');
    return { declaration, owner: value as unknown as Owner, scenarios };
  });
  const roots = plans.flatMap(({ owner }) => [owner.runtimeRoot, owner.tmpRoot, owner.sentinelRoot, owner.evidenceRoot].map(path => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path)));
  if (new Set(plans.map(({ owner }) => owner.project)).size !== 2 || new Set(plans.map(({ owner }) => owner.id)).size !== 2 || new Set(roots).size !== 8 || new Set(plans.flatMap(({ owner }) => Object.values(owner.ports))).size !== 6) throw new LabInvalidError('owner identity project port or root collision');
  for (const [index, root] of roots.entries()) for (const other of roots.slice(index + 1)) {
    const inside = relative(root, other), reverse = relative(other, root);
    if ((!inside.startsWith('..') && !isAbsolute(inside)) || (!reverse.startsWith('..') && !isAbsolute(reverse))) throw new LabInvalidError('owner roots cannot contain one another');
  }
  return plans;
}
