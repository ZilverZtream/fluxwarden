// Live comparison of the node adapters with the nodes' own command-line clients on the owned
// regtest lab. The plan names the compose project, the REST endpoints, the pinned certificates
// and the credential files by absolute path; credential bytes never enter the plan.
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { asRecord, repoRoot } from './cli.js';

export interface LabNode { service: string; host: string; port: number; tlsCert: string; credential: string; pubkey: string }
export interface AdapterLabPlan { project: string; composeFile: string; lnd: LabNode; cln: LabNode; wrongCert: string }

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw new Error(`adapter lab plan: ${what} is required`);
  return value;
}

function absolute(value: unknown, what: string): string {
  const path = text(value, what);
  if (!isAbsolute(path)) throw new Error(`adapter lab plan: ${what} must be an absolute path`);
  return path;
}

function node(value: unknown, credentialKey: 'macaroon' | 'rune', what: string): LabNode {
  const raw = asRecord(value, what);
  const port = raw['port'];
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`adapter lab plan: ${what}.port is invalid`);
  const pubkey = text(raw['pubkey'], `${what}.pubkey`);
  if (!/^(?:02|03)[0-9a-f]{64}$/.test(pubkey)) throw new Error(`adapter lab plan: ${what}.pubkey is invalid`);
  return {
    service: text(raw['service'], `${what}.service`), host: text(raw['host'], `${what}.host`), port,
    tlsCert: absolute(raw['tlsCert'], `${what}.tlsCert`), credential: absolute(raw[credentialKey], `${what}.${credentialKey}`), pubkey,
  };
}

/** Reads FLUXWARDEN_LAB_ADAPTER_PLAN before any Docker call; the plan must declare a disposable regtest lab. */
export function adapterLabPlan(input = process.env['FLUXWARDEN_LAB_ADAPTER_PLAN']): AdapterLabPlan {
  if (input === undefined || !isAbsolute(input)) throw new Error('an absolute FLUXWARDEN_LAB_ADAPTER_PLAN is required before Docker');
  const plan = asRecord(JSON.parse(readFileSync(input, 'utf8')) as unknown, 'adapter lab plan');
  if (plan['version'] !== 1 || plan['network'] !== 'regtest' || plan['disposable'] !== true) throw new Error('adapter lab plan must be version 1, regtest and disposable');
  const project = text(plan['project'], 'project');
  if (!/^fluxwarden-lab-[a-z0-9-]+$/.test(project)) throw new Error('adapter lab plan: project must be an owned lab project');
  return {
    project, composeFile: absolute(plan['composeFile'], 'composeFile'),
    lnd: node(plan['lnd'], 'macaroon', 'lnd'), cln: node(plan['cln'], 'rune', 'cln'), wrongCert: absolute(plan['wrongCert'], 'wrongCert'),
  };
}

function exec(plan: AdapterLabPlan, service: string, args: readonly string[]): unknown {
  const result = spawnSync('docker', ['compose', '--project-name', plan.project, '-f', plan.composeFile, 'exec', '-T', service, ...args],
    { shell: false, windowsHide: true, encoding: 'utf8', timeout: 60_000, maxBuffer: 64 * 1024 * 1024 });
  if (result.error !== undefined || result.status !== 0) throw new Error(`lab command on ${service} did not complete`);
  return JSON.parse(result.stdout) as unknown;
}

/** lncli prints protojson with proto names, every field, and bytes as hex (lnrpc/rpc_utils.go ProtoJSONMarshalOpts, UseHexForBytes). */
export function lncli(plan: AdapterLabPlan, args: readonly string[]): Record<string, unknown> {
  return asRecord(exec(plan, plan.lnd.service, ['lncli', '--network=regtest', ...args]), 'lncli answer');
}

export function lightningCli(plan: AdapterLabPlan, args: readonly string[]): Record<string, unknown> {
  return asRecord(exec(plan, plan.cln.service, ['lightning-cli', '--network=regtest', ...args]), 'lightning-cli answer');
}

export function rows(value: unknown, what: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error(`${what} must be a list`);
  return value.map(item => asRecord(item, what));
}

/** A JSON integer or decimal string as bigint; CLN "<n>msat" strings too. */
export function big(value: unknown): bigint {
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)(?:msat)?$/.test(value)) return BigInt(value.replace(/msat$/, ''));
  if (value === undefined || value === null) return 0n;
  throw new Error('not an integer');
}

/** The same sentinel scan as the other lab checks: product files, scratch and retained output. */
export async function expectNoSentinelLeak(): Promise<void> {
  const sentinelDir = process.env['FLUXWARDEN_SENTINEL_DIR'];
  const testTmp = process.env['FLUXWARDEN_TEST_TMP'];
  const evidenceDir = process.env['FLUXWARDEN_EVIDENCE_DIR'];
  if (!sentinelDir || !testTmp || !evidenceDir) throw new Error('isolated sentinel temporary and retained output roots are required');
  const sources = readdirSync(sentinelDir, { withFileTypes: true }).filter(entry => entry.isFile() && readFileSync(join(sentinelDir, entry.name)).length > 0);
  expect(sources.length, 'independent registered sentinels').toBeGreaterThanOrEqual(5);
  interface Scanner { findLeaks(options: { root: string; sentinelDir: string; sentinels: string; testTmp: string; evidenceDir: string; paths: string[] }): { path: string; encoding: string } | null }
  const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
  const inventory = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repoRoot, shell: false, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  expect(inventory.status, 'product file inventory').toBe(0);
  const paths = inventory.stdout.split('\0').filter(Boolean).map(path => join(repoRoot, path));
  expect(paths.length, 'product files scanned').toBeGreaterThan(0);
  const hit = scanner.findLeaks({ root: repoRoot, sentinelDir, sentinels: join(testTmp, 'sentinels.json'), testTmp, evidenceDir, paths: [...paths, testTmp, evidenceDir] });
  expect(hit).toBeNull();
}
