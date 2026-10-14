import { describe, expect, it } from 'vitest';
import { classify, openLab, LabInvalidError, type CommandResult, type Runner, type Service } from '../helpers/lab.js';

// Identity answers in the shapes the pinned nodes print: lnd GetInfo over lncli
// (`chains[].network`, `version` "0.21.4-beta commit=…", L20) and CLN getinfo
// (`network`, `version`, C18). Pubkeys are arbitrary valid-looking keys.
const keys: Record<string, string> = {
  'lnd-p': `02${'a1'.repeat(32)}`, 'lnd-r': `03${'b2'.repeat(32)}`, 'cln-p': `02${'c3'.repeat(32)}`, 'cln-r': `03${'d4'.repeat(32)}`, 'cln-m': `02${'e5'.repeat(32)}`,
};
type Identity = { network?: string; version?: string };
function stub(overrides: Partial<Record<Service, Identity>> = {}): { run: Runner; calls: string[][] } {
  const calls: string[][] = [];
  const ok = (value: unknown): CommandResult => ({ exitCode: 0, stdout: JSON.stringify(value), stderr: '' });
  const run: Runner = (service, argv) => {
    calls.push([service, ...argv]);
    const method = argv.find(arg => ['getinfo', 'getblockchaininfo', 'getnetworkinfo'].includes(arg));
    const wanted = overrides[service] ?? {};
    if (service === 'bitcoind') {
      if (method === 'getblockchaininfo') return ok({ chain: wanted.network ?? 'regtest', blocks: 113 });
      if (method === 'getnetworkinfo') return ok({ version: 310100, subversion: wanted.version ?? '/Satoshi:31.1.0/' });
    } else if (method === 'getinfo') {
      return service.startsWith('lnd-')
        ? ok({ identity_pubkey: keys[service], version: wanted.version ?? '0.21.4-beta commit=v0.21.4-beta', chains: [{ chain: 'bitcoin', network: wanted.network ?? 'regtest' }], block_height: 113 })
        : ok({ id: keys[service], version: wanted.version ?? 'v26.06.9', network: wanted.network ?? 'regtest', blockheight: 113 });
    }
    // Any other command would be a fact body running before the guard.
    return ok({ unexpected: argv });
  };
  return { run, calls };
}
const declaration = { project: 'fluxwarden-lab-stub' };
const identityOnly = (calls: string[][]): boolean => calls.every(call => call.some(arg => ['getinfo', 'getblockchaininfo', 'getnetworkinfo'].includes(arg)));

describe('lab facts suite guard', () => {
  it('CP-010/B1 a pinned regtest lab opens and yields the observed node keys', () => {
    const { run, calls } = stub();
    const opened = openLab({ run, declaration });
    expect(opened.pubkeys).toEqual(keys);
    expect(identityOnly(calls)).toBe(true);
    // lncli and lightning-cli run with the regtest network flag (lnd cmd/commands; lightningd options).
    expect(calls.filter(call => call[0] === 'lnd-r')).toEqual([['lnd-r', 'lncli', '--network=regtest', 'getinfo']]);
    expect(calls.filter(call => call[0] === 'cln-m')).toEqual([['cln-m', 'lightning-cli', '--network=regtest', '-k', 'getinfo']]);
  });

  // INV-15 / SPEC 11.1 LU4: a node on signet or at another version invalidates the run.
  it.each<[string, Partial<Record<Service, Identity>>]>([
    ['LND on signet', { 'lnd-r': { network: 'signet' } }],
    ['CLN on signet', { 'cln-m': { network: 'signet' } }],
    ['LND at 0.21.3-beta', { 'lnd-p': { version: '0.21.3-beta commit=v0.21.3-beta' } }],
    ['LND at 0.21.40-beta', { 'lnd-r': { version: '0.21.40-beta commit=v0.21.40-beta' } }],
    ['CLN at v26.06.8', { 'cln-r': { version: 'v26.06.8' } }],
    ['CLN with a custom version suffix', { 'cln-p': { version: 'v26.06.9-modded' } }],
    ['bitcoind on testnet4', { bitcoind: { network: 'testnet4' } }],
    ['bitcoind at another release', { bitcoind: { version: '/Satoshi:30.0.0/' } }],
  ])('CP-010/B1 %s throws LabInvalidError before any fact command', (_name, overrides) => {
    const { run, calls } = stub(overrides);
    expect(() => openLab({ run, declaration })).toThrow(LabInvalidError);
    expect(calls.length).toBeGreaterThan(0);
    expect(identityOnly(calls)).toBe(true);
  });

  it('CP-010/B1 an unreachable node is LabInvalidError, not a passing guard', () => {
    const { run } = stub();
    const failing: Runner = (service, argv) => service === 'cln-r' ? { exitCode: 2, stdout: '', stderr: 'lightning-cli: Connecting to \'lightning-rpc\': Connection refused' } : run(service, argv);
    expect(() => openLab({ run: failing, declaration })).toThrow(LabInvalidError);
  });
});

describe('oracle outcome mapping', () => {
  // lnd cmd/lncli/main.go: `[lncli] <err>` on stderr, exit 1; gRPC status text "rpc error: code = X desc = Y".
  it('CP-010/B2 lncli exit codes map to accepted, rejected with the gRPC code, and error', () => {
    expect(classify('lnd-r', { exitCode: 0, stdout: '{\n    "state": "OPEN"\n}\n', stderr: '' })).toEqual({ kind: 'accepted', value: { state: 'OPEN' } });
    expect(classify('lnd-r', { exitCode: 1, stdout: '', stderr: '[lncli] rpc error: code = NotFound desc = unable to locate invoice\n' }))
      .toEqual({ kind: 'rejected', code: 'NotFound', message: 'unable to locate invoice' });
    expect(classify('lnd-p', { exitCode: 1, stdout: '', stderr: '[lncli] rpc error: code = Unknown desc = invoice is already paid\n' }))
      .toEqual({ kind: 'rejected', code: 'Unknown', message: 'invoice is already paid' });
    // Local lncli failures never reached the node.
    expect(classify('lnd-r', { exitCode: 1, stdout: '', stderr: '[lncli] unable to unmarshal json string from incoming array of routes\n' }).kind).toBe('error');
    // grpc-go raises Unavailable / DeadlineExceeded in the client when lnd never answered.
    expect(classify('lnd-r', { exitCode: 1, stdout: '', stderr: '[lncli] rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing"\n' }).kind).toBe('error');
    expect(classify('lnd-r', { exitCode: 1, stdout: '', stderr: '[lncli] rpc error: code = DeadlineExceeded desc = context deadline exceeded\n' }).kind).toBe('error');
    expect(classify('lnd-r', { exitCode: 0, stdout: 'not json', stderr: '' }).kind).toBe('error');
    expect(classify('lnd-r', { exitCode: 126, stdout: '', stderr: '[lncli] rpc error: code = NotFound desc = x' }).kind).toBe('error');
    expect(classify('lnd-r', { exitCode: null, stdout: '', stderr: '' }).kind).toBe('error');
  });

  // doc/lightning-cli.1.md: exit 1 = lightningd error reply (printed JSON), 2 = no connection, 3 = usage.
  it('CP-010/B2 lightning-cli error replies map to rejected with the lightningd code', () => {
    expect(classify('cln-m', { exitCode: 0, stdout: '{\n   "layers": []\n}\n', stderr: '' })).toEqual({ kind: 'accepted', value: { layers: [] } });
    expect(classify('cln-m', { exitCode: 1, stdout: '{\n   "code": 208,\n   "message": "Never attempted payment part 0"\n}\n', stderr: '' }))
      .toEqual({ kind: 'rejected', code: 208, message: 'Never attempted payment part 0' });
    expect(classify('cln-r', { exitCode: 1, stdout: '{"code": -32602, "message": "source and destination must be different"}', stderr: '' }))
      .toEqual({ kind: 'rejected', code: -32602, message: 'source and destination must be different' });
    // lightning-cli prints JSON-RPC notifications as "# " lines ahead of the reply (askrene getroutes progress).
    expect(classify('cln-m', { exitCode: 0, stdout: '# Flow 0/1: 100202101msat/148 108x3x0/1\n{\n   "routes": []\n}\n', stderr: '' })).toEqual({ kind: 'accepted', value: { routes: [] } });
    expect(classify('cln-m', { exitCode: 1, stdout: '# minflow failed: unable to find a feasible flow.\n{\n   "code": 205,\n   "message": "We could not find a usable set of paths."\n}\n', stderr: '' }))
      .toEqual({ kind: 'rejected', code: 205, message: 'We could not find a usable set of paths.' });
    expect(classify('cln-m', { exitCode: 2, stdout: '', stderr: 'Connecting to \'lightning-rpc\': Connection refused' }).kind).toBe('error');
    expect(classify('cln-m', { exitCode: 3, stdout: '', stderr: 'lightning-cli: Unknown parameter' }).kind).toBe('error');
    expect(classify('cln-m', { exitCode: 1, stdout: 'garbled', stderr: '' }).kind).toBe('error');
    expect(classify('cln-m', { exitCode: 1, stdout: '{"code": "208", "message": "x"}', stderr: '' }).kind).toBe('error');
    expect(classify('cln-m', { exitCode: 125, stdout: '{"code": 208, "message": "x"}', stderr: '' }).kind).toBe('error');
  });

  // src/bitcoin-cli.cpp: "error code: <n>" then "error message:", exit status |n|.
  it('CP-010/B2 bitcoin-cli RPC errors map to rejected and plain answers are accepted', () => {
    expect(classify('bitcoind', { exitCode: 0, stdout: '113\n', stderr: '' })).toEqual({ kind: 'accepted', value: 113 });
    expect(classify('bitcoind', { exitCode: 0, stdout: 'bcrt1qexampleaddress\n', stderr: '' })).toEqual({ kind: 'accepted', value: 'bcrt1qexampleaddress' });
    expect(classify('bitcoind', { exitCode: 8, stdout: '', stderr: 'error code: -8\nerror message:\nblockhash must be of length 64\n' }))
      .toEqual({ kind: 'rejected', code: -8, message: 'blockhash must be of length 64' });
    expect(classify('bitcoind', { exitCode: 1, stdout: '', stderr: 'error: Could not connect to the server 127.0.0.1:18443\n' }).kind).toBe('error');
  });
});
