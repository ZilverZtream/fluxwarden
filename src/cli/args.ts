// Argument parsing. The result never carries an unknown token from argv, so no later
// stage can echo one; values of known options are kept for the command.

export type UsageReason =
  | 'missing command' | 'unknown command' | 'unknown option' | 'missing option value' | 'repeated option'
  | 'unexpected operand' | 'missing operand' | 'unknown sort key' | 'daemon needs --collect' | 'keys generate needs --out';

export type SortKey = 'inbound-deficit' | 'outbound' | 'capacity';
export const SORT_KEYS: readonly SortKey[] = ['inbound-deficit', 'outbound', 'capacity'];

/** Connection settings given as flags (one source, SECURITY.md §3.3: paths, never values). */
export interface ConnectionFlags {
  readonly url?: string;
  readonly tlsCertPath?: string;
  readonly macaroonPath?: string;
  readonly runePath?: string;
}

/** Flag names of the connection settings, in the order they are reported. */
export const CONNECTION_FLAGS: readonly (readonly [keyof ConnectionFlags, string])[] = [
  ['url', '--url'], ['tlsCertPath', '--tls-cert-path'], ['macaroonPath', '--macaroon-path'], ['runePath', '--rune-path'],
];

interface Common { readonly json: boolean; readonly config: string; readonly connection: ConnectionFlags }

export type Command =
  | Common & { readonly kind: 'lab up' | 'lab down'; readonly seed: string | null }
  | Common & { readonly kind: 'lab workload'; readonly type: string | null; readonly count: string | null; readonly seed: string | null }
  | Common & { readonly kind: 'lab chaos'; readonly caseId: string | null; readonly seed: string | null }
  | Common & { readonly kind: 'doctor' }
  | Common & { readonly kind: 'nodes list' }
  | Common & { readonly kind: 'nodes inspect'; readonly node: string; readonly capabilities: boolean }
  | Common & { readonly kind: 'channels'; readonly node: string | null; readonly sort: SortKey | null }
  | Common & { readonly kind: 'daemon'; readonly collect: boolean }
  | Common & { readonly kind: 'liquidity diagnose' | 'liquidity plan'; readonly node: string | null; readonly horizon: string | null; readonly policy: string | null; readonly refresh: boolean }
  | Common & { readonly kind: 'liquidity explain'; readonly proposalId: string }
  | Common & { readonly kind: 'liquidity approve'; readonly proposalId: string; readonly key: string | null; readonly maxFee: string | null; readonly maxCltv: string | null; readonly expiresIn: string | null }
  | Common & { readonly kind: 'actions execute'; readonly proposalId: string; readonly requireRegtest: boolean }
  | Common & { readonly kind: 'actions status'; readonly executionId: string; readonly watch: boolean }
  | Common & { readonly kind: 'ledger verify' }
  | Common & { readonly kind: 'reconcile'; readonly node: string | null; readonly since: string | null; readonly until: string | null }
  | Common & { readonly kind: 'evidence export'; readonly runId: string | null; readonly out: string | null }
  | Common & { readonly kind: 'keys generate'; readonly out: string };

export type Parsed =
  | { readonly kind: 'help'; readonly json: boolean }
  | { readonly kind: 'version'; readonly json: boolean }
  | { readonly kind: 'usage'; readonly json: boolean; readonly command: string | null; readonly reason: UsageReason }
  | { readonly kind: 'command'; readonly command: Command };

export const DEFAULT_CONFIG = 'fluxwarden.yaml';

const COMMANDS = new Set(['doctor', 'nodes', 'channels', 'daemon', 'keys', 'liquidity', 'actions', 'ledger', 'reconcile', 'evidence', 'lab']);
/** Options taking a value, by command name; every command takes --config and the connection flags. */
const VALUE_OPTIONS: Readonly<Record<string, readonly string[]>> = {
  'lab up': ['--seed'], 'lab down': [], 'lab workload': ['--type', '--count', '--seed'], 'lab chaos': ['--case', '--seed'],
  doctor: [], 'nodes list': [], 'nodes inspect': [], channels: ['--node', '--sort'], daemon: [], 'keys generate': ['--out'],
  'liquidity diagnose': ['--node', '--horizon'], 'liquidity plan': ['--node', '--horizon', '--policy'], 'liquidity explain': [],
  'liquidity approve': ['--key', '--max-fee-msat', '--max-cltv-delta', '--expires-in'], 'actions execute': [], 'actions status': [],
  'ledger verify': [], reconcile: ['--node', '--since', '--until'], 'evidence export': ['--run-id', '--out'],
};
const SWITCHES: Readonly<Record<string, readonly string[]>> = {
  'lab up': [], 'lab down': [], 'lab workload': [], 'lab chaos': ['--all'],
  doctor: [], 'nodes list': [], 'nodes inspect': ['--capabilities'], channels: [], daemon: ['--collect'], 'keys generate': [],
  'liquidity diagnose': [], 'liquidity plan': ['--refresh'], 'liquidity explain': [], 'liquidity approve': [],
  'actions execute': ['--require-regtest'], 'actions status': ['--watch'], 'ledger verify': [], reconcile: [], 'evidence export': [],
};
const SHARED_VALUE_OPTIONS = ['--config', ...CONNECTION_FLAGS.map(([, flag]) => flag)];

class Usage extends Error {
  constructor(readonly reason: UsageReason) {
    super(reason);
    this.name = 'Usage';
  }
}

export function parseArgs(argv: readonly string[]): Parsed {
  let json = false;
  let help = false;
  let version = false;
  let operandsOnly = false;
  const tokens: { text: string; operand: boolean }[] = [];
  for (const token of argv) {
    if (!operandsOnly && token === '--') operandsOnly = true;
    else if (!operandsOnly && token === '--json') json = true;
    else if (!operandsOnly && token === '--help') help = true;
    else if (!operandsOnly && token === '--version') version = true;
    else tokens.push({ text: token, operand: operandsOnly || !token.startsWith('-') || token === '-' });
  }
  const first = tokens[0];
  if (help || version) {
    if (first !== undefined) return { kind: 'usage', json, command: null, reason: first.operand ? 'unknown command' : 'unknown option' };
    return help ? { kind: 'help', json } : { kind: 'version', json };
  }
  if (first === undefined) return { kind: 'usage', json, command: null, reason: 'missing command' };
  if (!first.operand || !COMMANDS.has(first.text)) return { kind: 'usage', json, command: null, reason: first.operand ? 'unknown command' : 'unknown option' };
  let name = first.text;
  let rest = tokens.slice(1);
  if (['nodes', 'liquidity', 'actions', 'ledger', 'evidence', 'lab'].includes(name)) {
    const sub = rest[0];
    if (sub === undefined || !sub.operand) return { kind: 'usage', json, command: null, reason: 'missing command' };
    if (VALUE_OPTIONS[`${name} ${sub.text}`] === undefined) return { kind: 'usage', json, command: null, reason: 'unknown command' };
    name = `${name} ${sub.text}`;
    rest = rest.slice(1);
  } else if (name === 'keys') {
    const sub = rest[0];
    if (sub === undefined || !sub.operand) return { kind: 'usage', json, command: null, reason: 'missing command' };
    if (sub.text !== 'generate') return { kind: 'usage', json, command: null, reason: 'unknown command' };
    name = 'keys generate';
    rest = rest.slice(1);
  }
  try {
    return { kind: 'command', command: commandFrom(name, rest, json) };
  } catch (error) {
    if (error instanceof Usage) return { kind: 'usage', json, command: name, reason: error.reason };
    throw error;
  }
}

function commandFrom(name: string, tokens: readonly { text: string; operand: boolean }[], json: boolean): Command {
  const values = new Map<string, string>();
  const switches = new Set<string>();
  const operands: string[] = [];
  const valueOptions = [...SHARED_VALUE_OPTIONS, ...(VALUE_OPTIONS[name] ?? [])];
  const switchOptions = SWITCHES[name] ?? [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === undefined) break;
    if (token.operand) { operands.push(token.text); continue; }
    const equals = token.text.indexOf('=');
    const option = equals === -1 ? token.text : token.text.slice(0, equals);
    if (valueOptions.includes(option)) {
      let value: string | undefined;
      if (equals !== -1) value = token.text.slice(equals + 1);
      else {
        const next = tokens[index + 1];
        if (next === undefined || (!next.operand && next.text.startsWith('--'))) throw new Usage('missing option value');
        value = next.text;
        index += 1;
      }
      if (value === '') throw new Usage('missing option value');
      if (values.has(option)) throw new Usage('repeated option');
      values.set(option, value);
    } else if (switchOptions.includes(option) && equals === -1) {
      if (switches.has(option)) throw new Usage('repeated option');
      switches.add(option);
    } else {
      throw new Usage('unknown option');
    }
  }
  const connection: ConnectionFlags = Object.fromEntries(
    CONNECTION_FLAGS.flatMap(([key, flag]) => { const value = values.get(flag); return value === undefined ? [] : [[key, value]]; }),
  );
  const common: Common = { json, config: values.get('--config') ?? DEFAULT_CONFIG, connection };
  switch (name) {
    case 'lab up':
    case 'lab down':
      if (operands.length > 0) throw new Usage('unexpected operand');
      return { ...common, kind: name, seed: values.get('--seed') ?? null };
    case 'lab workload':
      if (operands.length > 0) throw new Usage('unexpected operand');
      return { ...common, kind: name, type: values.get('--type') ?? null, count: values.get('--count') ?? null, seed: values.get('--seed') ?? null };
    case 'lab chaos':
      if (operands.length > 1 || (operands.length > 0 && values.has('--case')) || (switches.has('--all') && (operands.length > 0 || values.has('--case')))) throw new Usage('unexpected operand');
      return { ...common, kind: name, caseId: switches.has('--all') ? 'T-05' : values.get('--case') ?? operands[0] ?? null, seed: values.get('--seed') ?? null };
    case 'liquidity diagnose':
    case 'liquidity plan':
      if (operands.length > 0) throw new Usage('unexpected operand');
      return { ...common, kind: name, node: values.get('--node') ?? null, horizon: values.get('--horizon') ?? null, policy: values.get('--policy') ?? null, refresh: switches.has('--refresh') };
    case 'liquidity explain':
    case 'liquidity approve':
    case 'actions execute':
    case 'actions status': {
      const id = operands[0];
      if (id === undefined) throw new Usage('missing operand');
      if (operands.length > 1) throw new Usage('unexpected operand');
      if (name === 'liquidity explain') return { ...common, kind: name, proposalId: id };
      if (name === 'liquidity approve') return { ...common, kind: name, proposalId: id, key: values.get('--key') ?? null, maxFee: values.get('--max-fee-msat') ?? null, maxCltv: values.get('--max-cltv-delta') ?? null, expiresIn: values.get('--expires-in') ?? null };
      if (name === 'actions execute') return { ...common, kind: name, proposalId: id, requireRegtest: switches.has('--require-regtest') };
      return { ...common, kind: name, executionId: id, watch: switches.has('--watch') };
    }
    case 'ledger verify':
      if (operands.length > 0) throw new Usage('unexpected operand');
      return { ...common, kind: name };
    case 'reconcile':
      if (operands.length > 0) throw new Usage('unexpected operand');
      return { ...common, kind: name, node: values.get('--node') ?? null, since: values.get('--since') ?? null, until: values.get('--until') ?? null };
    case 'evidence export':
      if (operands.length > 0) throw new Usage('unexpected operand');
      return { ...common, kind: name, runId: values.get('--run-id') ?? null, out: values.get('--out') ?? null };
    case 'doctor':
    case 'nodes list':
    case 'daemon': {
      if (operands.length > 0) throw new Usage('unexpected operand');
      if (name === 'daemon') {
        return { ...common, kind: 'daemon', collect: switches.has('--collect') };
      }
      return { ...common, kind: name };
    }
    case 'keys generate': {
      if (operands.length > 0) throw new Usage('unexpected operand');
      const out = values.get('--out');
      if (out === undefined) throw new Usage('keys generate needs --out');
      return { ...common, kind: 'keys generate', out };
    }
    case 'nodes inspect': {
      const node = operands[0];
      if (node === undefined) throw new Usage('missing operand');
      if (operands.length > 1) throw new Usage('unexpected operand');
      return { ...common, kind: 'nodes inspect', node, capabilities: switches.has('--capabilities') };
    }
    default: {
      if (operands.length > 0) throw new Usage('unexpected operand');
      const sort = values.get('--sort');
      if (sort !== undefined && !SORT_KEYS.some(key => key === sort)) throw new Usage('unknown sort key');
      return { ...common, kind: 'channels', node: values.get('--node') ?? null, sort: (SORT_KEYS.find(key => key === sort) ?? null) };
    }
  }
}
