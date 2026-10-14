/*
Interface: scripts/make-fixtures.mjs, the recordings tool.

CLI
  node scripts/make-fixtures.mjs --owner <absolute owner.json> [--out <absolute directory>]
    --owner  the owner declaration given to `labs/docker/lab.mjs up --owner`. The tool reads
             <runtimeRoot>/lab.json (ports, credential paths) and drives only that running lab.
    --out    output root, default <repo>/labs/fixtures.
  Exit 0 recorded; 1 refused or failed; 2 usage. On exit 1 nothing is left in --out by this run:
  the guards run before any file or directory is created, and a later failure removes what the
  run created. `npm run fixtures:record -- --owner <file>` runs it.

Guards (before anything is written, using only GetInfo / getinfo of the two recorded nodes):
  lnd-r GET /v1/getinfo: chains[0].network === 'regtest' and version starts '0.21.4-beta' then end or ' ';
  cln-m POST /v1/getinfo: network === 'regtest' and version === 'v26.06.9'. Anything else, or a
  non-2xx answer, is exit 1.

Output layout
  <out>/recordings/<impl>/<version>/<id>.json   impl 'lnd' | 'cln'; version '0.21.4-beta' | 'v26.06.9'
  <out>/manifest.json
  A recording file is JSON:
    { "id", "impl", "version", "node": "lnd-r" | "cln-m",
      "request":  { "method": "GET" | "POST", "path": "/v1/...", "body": <JSON value or null> },
      "response": { "status": <int>, "body": "<raw response text>" }          unary call
               or { "status": <int>, "lines": ["<raw NDJSON line>", ...] }      stream }
  manifest.json:
    { "version": 1,
      "entries": [ { "file": "recordings/<impl>/<version>/<id>.json", "id", "impl", "version",
                     "sha256": "<lowercase hex of the file bytes>",
                     "command": { "transport": "lnd-rest" | "clnrest", "method", "path", "body" },
                     "source": "lab" } ] }
  `command` is the request that produced the file and equals the recording's `request`
  (transport lnd-rest for lnd-r through lnd-r-rest, clnrest `POST /v1/<method>` for cln-m through
  cln-m-rest). Historical profiles (LND 0.20, CLN 26.04) may be added only from separately
  pinned lab observations or authenticated upstream fixtures. A separately pinned lab
  entry has "source": "lab" and "provenance" with the release URL, source commit,
  immutable image, daemon/CLI hashes, capture command, oracle hash and observed network/version.
  An upstream entry has "source": "upstream", "url":
  "https://github.com/<owner>/<repo>/blob/<40-hex commit>/<path>" and "upstreamSha256".
  Nothing is synthesised.

Recordings (ids), captured from a freshly brought-up lab; snapshots before any payment.
  lnd/0.21.4-beta (lnd-r):
    getinfo              GET  /v1/getinfo
    listchannels         GET  /v1/channels
    pendingchannels      GET  /v1/channels/pending
    queryroutes          POST /v1/graph/routes/<lnd-r pubkey>/0  { amt_msat: "100000000",
                         outgoing_chan_ids: [<channel 3 chan_id>], last_hop_pubkey: <base64 cln-m pubkey>,
                         fee_limit: { fixed_msat: "10000000" }, use_mission_control: true }
    track-succeeded      GET  /v2/router/track/<padded base64url hash>, opened while lnd-r's
                         SendToRouteV2 to a hold invoice of lnd-p over channel 1 is held, read until
                         the line after the hold is settled
    track-failed         GET  /v2/router/track/<hash> after SendToRouteV2 to an unknown hash at lnd-p
    error-code-message   GET  /v1/invoice/<64 zeros>                    (404 {code, message, details})
    error-envelope       GET  /v2/router/track/<base64url of 32 zero bytes>= (404 {"error": {...}})
    (the third envelope, {"result": {...}}, is every line of the track recordings)
  cln/v26.06.9 (cln-m, clnrest POST /v1/<method>, JSON body = params):
    getinfo              {}
    listpeerchannels     {}
    listchannels         {}
    getroutes            { source: <lnd-r>, destination: <cln-r>, amount_msat: 100000000,
                           layers: ["auto.localchans"], maxfee_msat: 10000000, final_cltv: 34, maxparts: 1 }
    waitsendpay-200      { payment_hash: <h>, timeout: 1 } while cln-m's sendpay to a hold invoice of
                         lnd-p (route cln-m -> lnd-r -> lnd-p) is held
    listsendpays         { payment_hash: <h> } after the hold is settled
    listpays             { payment_hash: <h> }
    bkpr-listaccountevents {}
  Hold creation uses container CLI commands; secret-bearing settlement uses pinned HTTPS
  to LND-P through the owner's temporarily re-aimed proxy, restored after each request. The tool
  uses the lab's role credentials where they allow a call; for any other call it bakes a
  temporary macaroon or creates a temporary rune with the container CLI and revokes it before exit.

Redaction (applied to every response text before it is written)
  export function redactText(text: string, secrets: Uint8Array[]): string
  1. The string value of every "payment_preimage", "r_preimage" or "preimage" member that decodes
     (64 hex digits, or base64 of 32 bytes) to 32 bytes that are not all zero becomes
     "fp:<first 16 hex digits of sha256(those bytes)>". All-zero values ("no preimage") stay.
  2. Every remaining occurrence of a registered secret, as raw text, lowercase hex, uppercase hex,
     base64, base64 without padding, base64url or base64url with padding, becomes
     "[redacted fp:<first 16 hex digits of sha256(secret)>]".
  Everything else is kept byte for byte (uint64 numbers stay exact). The tool registers each
  preimage it generates and every credential it reads or creates, and writes each such secret to
  the owner's sentinelRoot as recording-<n>.bin before first use.

Module exports used by the tests
  export async function main(argv: string[], deps?: { transport?: Transport; exec?: Exec }): Promise<number>
  type Transport = (request: { node: 'lnd-p' | 'lnd-r' | 'cln-m'; method: 'GET' | 'POST'; path: string;
                               body?: unknown; stream?: boolean }) => Promise<{ status: number; body: string }>
    (body is the raw response text; for a stream the raw NDJSON text)
  type Exec = (service: string, argv: string[]) => Promise<{ exitCode: number; stdout: string; stderr: string }>
*/
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { asRecord, isRecord, repoRoot, scratchDir } from '../helpers/cli.js';
import { secretForms } from '../helpers/output.js';

interface Transport { (request: { node: 'lnd-r' | 'cln-m'; method: 'GET' | 'POST'; path: string; body?: unknown; stream?: boolean }): Promise<{ status: number; body: string }> }
interface Exec { (service: string, argv: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> }
interface Tool {
  main: (argv: string[], deps?: { transport?: Transport; exec?: Exec }) => Promise<number>;
  redactText: (text: string, secrets: Uint8Array[]) => string;
}
const tool = async (): Promise<Tool> => await import(pathToFileURL(join(repoRoot, 'scripts/make-fixtures.mjs')).href) as Tool;

const fixtures = join(repoRoot, 'labs', 'fixtures');
const profiles = { lnd: '0.21.4-beta', cln: 'v26.06.9' } as const;
const required = {
  lnd: ['getinfo', 'listchannels', 'pendingchannels', 'queryroutes', 'track-succeeded', 'track-failed', 'error-code-message', 'error-envelope'],
  cln: ['getinfo', 'listpeerchannels', 'listchannels', 'getroutes', 'waitsendpay-200', 'listsendpays', 'listpays', 'bkpr-listaccountevents'],
} as const;
type Impl = keyof typeof profiles;

function manifest(): Record<string, unknown>[] {
  const path = join(fixtures, 'manifest.json');
  expect(existsSync(path), 'labs/fixtures/manifest.json is committed').toBe(true);
  const value = asRecord(JSON.parse(readFileSync(path, 'utf8')) as unknown, 'manifest');
  expect(value['version']).toBe(1);
  const entries = value['entries'];
  if (!Array.isArray(entries)) throw new Error('manifest entries must be a list');
  return entries.map(entry => asRecord(entry, 'manifest entry'));
}
function recording(impl: Impl, id: string): Record<string, unknown> {
  return asRecord(JSON.parse(readFileSync(join(fixtures, 'recordings', impl, profiles[impl], `${id}.json`), 'utf8')) as unknown, `${impl} ${id}`);
}
function response(impl: Impl, id: string): Record<string, unknown> { return asRecord(recording(impl, id)['response'], `${impl} ${id} response`); }
function body(impl: Impl, id: string): Record<string, unknown> {
  const raw = response(impl, id)['body'];
  if (typeof raw !== 'string') throw new Error(`${impl} ${id} has no raw body`);
  return asRecord(JSON.parse(raw) as unknown, `${impl} ${id} body`);
}
function lines(impl: Impl, id: string): Record<string, unknown>[] {
  const raw = response(impl, id)['lines'];
  if (!Array.isArray(raw) || !raw.every(line => typeof line === 'string')) throw new Error(`${impl} ${id} has no raw stream lines`);
  return raw.map(line => asRecord(JSON.parse(line) as unknown, `${impl} ${id} line`));
}
function filesUnder(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory).flatMap(name => { const path = join(directory, name); return statSync(path).isDirectory() ? filesUnder(path) : [path]; });
}

describe('committed recordings', () => {
  it('CP-009/B1 every manifest entry names an existing file with its version, SHA-256 and producing command', () => {
    const entries = manifest();
    expect(entries.length).toBeGreaterThanOrEqual(required.lnd.length + required.cln.length);
    const listed = new Set<string>();
    for (const entry of entries) {
      const file = entry['file'];
      expect(typeof file === 'string' && /^recordings\/(lnd|cln)\/[^/]+\/[a-z0-9-]+\.json$/.test(file), `entry file ${String(file)}`).toBe(true);
      const [, impl, version, name] = String(file).split('/');
      const path = join(fixtures, String(file));
      expect(existsSync(path), `${String(file)} exists`).toBe(true);
      listed.add(String(file));
      expect([entry['impl'], entry['version'], entry['id']]).toEqual([impl, version, name?.replace(/\.json$/, '')]);
      expect(entry['sha256']).toBe(createHash('sha256').update(readFileSync(path)).digest('hex'));
      const content = asRecord(JSON.parse(readFileSync(path, 'utf8')) as unknown, String(file));
      expect([content['id'], content['impl'], content['version']]).toEqual([entry['id'], impl, version]);
      const command = asRecord(entry['command'], 'command'), request = asRecord(content['request'], 'request');
      expect(command['transport']).toBe(impl === 'lnd' ? 'lnd-rest' : 'clnrest');
      expect({ method: command['method'], path: command['path'], body: command['body'] }).toEqual({ method: request['method'], path: request['path'], body: request['body'] });
      if (impl === 'cln') expect([request['method'], request['path']]).toEqual(['POST', `/v1/${String(name?.replace(/\.json$/, '').replace(/-200$/, ''))}`]);
      if (entry['source'] === 'lab') continue;
      // Historical profiles only from authenticated upstream fixtures, never synthesised.
      expect(entry['source']).toBe('upstream');
      expect(entry['url']).toMatch(/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/blob\/[0-9a-f]{40}\/\S+$/);
      expect(entry['upstreamSha256']).toMatch(/^[0-9a-f]{64}$/);
    }
    // No unlisted or tampered-in file under recordings/.
    expect(filesUnder(join(fixtures, 'recordings')).map(path => relative(fixtures, path).split('\\').join('/')).sort()).toEqual([...listed].sort());
    // The pinned versions are the ones the nodes reported.
    expect(String(asRecord(body('lnd', 'getinfo'), 'lnd getinfo')['version'])).toMatch(/^0\.21\.4-beta(?: |$)/);
    expect(body('cln', 'getinfo')['version']).toBe('v26.06.9');
  });

  it('CP-009/B2 the pinned profiles cover every required answer with the observed wire shapes', () => {
    const ids = new Set(manifest().filter(entry => entry['source'] === 'lab').map(entry => `${String(entry['impl'])}/${String(entry['version'])}/${String(entry['id'])}`));
    for (const impl of ['lnd', 'cln'] as const) for (const id of required[impl]) expect(ids.has(`${impl}/${profiles[impl]}/${id}`), `${impl} ${id}`).toBe(true);
    // LND GetInfo network is chains[].network (L20); lnd-r has channels 1, 2 and 3.
    const info = body('lnd', 'getinfo');
    expect([response('lnd', 'getinfo')['status'], (info['chains'] as Record<string, unknown>[] | undefined)?.[0]?.['network']]).toEqual([200, 'regtest']);
    expect(body('lnd', 'listchannels')['channels']).toHaveLength(3);
    expect(Object.keys(body('lnd', 'pendingchannels')).sort()).toEqual(['pending_closing_channels', 'pending_force_closing_channels', 'pending_open_channels', 'total_limbo_balance', 'waiting_close_channels']);
    expect(body('lnd', 'queryroutes')['routes']).toHaveLength(1);
    // The three envelopes on one stream endpoint and one unary endpoint (FC-002, L23).
    const order = ['INITIATED', 'IN_FLIGHT', 'SUCCEEDED'];
    const succeeded = lines('lnd', 'track-succeeded').map(line => { expect(Object.keys(line)).toEqual(['result']); return String(asRecord(line['result'], 'result')['status']); });
    expect(succeeded.every(status => order.includes(status))).toBe(true);
    expect(succeeded.map(status => order.indexOf(status))).toEqual([...succeeded.map(status => order.indexOf(status))].sort((a, b) => a - b));
    expect([succeeded.includes('IN_FLIGHT'), succeeded.at(-1)]).toEqual([true, 'SUCCEEDED']);
    const failed = lines('lnd', 'track-failed').map(line => asRecord(line['result'], 'result')).at(-1);
    expect([failed?.['status'], failed?.['failure_reason']]).toEqual(['FAILED', 'FAILURE_REASON_INCORRECT_PAYMENT_DETAILS']);
    expect([response('lnd', 'error-code-message')['status'], body('lnd', 'error-code-message')]).toEqual([404, { code: 5, message: 'unable to locate invoice', details: [] }]);
    expect(response('lnd', 'error-envelope')['status']).toBe(404);
    expect(body('lnd', 'error-envelope')).toEqual({ error: { code: 5, message: "payment isn't initiated", details: [] } });
    // clnrest: success is 201; a lightningd error is a non-2xx answer carrying its code (C7: 200 = still in flight).
    expect([response('cln', 'getinfo')['status'], body('cln', 'getinfo')['network']]).toEqual([201, 'regtest']);
    expect(body('cln', 'listpeerchannels')['channels']).toHaveLength(2);
    const path = (body('cln', 'getroutes')['routes'] as Record<string, unknown>[] | undefined)?.[0]?.['path'];
    expect(Array.isArray(path) && path.length > 0 && path.every(hop => isRecord(hop) && typeof hop['node_id_out'] === 'string' && 'amount_out_msat' in hop && 'cltv_out' in hop)).toBe(true);
    const waiting = response('cln', 'waitsendpay-200');
    expect([Number(waiting['status']) >= 400, body('cln', 'waitsendpay-200')['code']]).toEqual([true, 200]);
    expect((body('cln', 'listsendpays')['payments'] as Record<string, unknown>[]).map(part => part['status'])).toEqual(['complete']);
    expect((body('cln', 'listpays')['pays'] as Record<string, unknown>[]).map(pay => pay['status'])).toEqual(['complete']);
    expect((body('cln', 'bkpr-listaccountevents')['events'] as unknown[]).length).toBeGreaterThan(0);
  });

  it('CP-009/B3 committed recordings carry preimages only as fingerprints and no sentinel in any encoding', () => {
    const files = filesUnder(join(fixtures, 'recordings'));
    expect(files.length).toBeGreaterThan(0);
    const preimages: string[] = [];
    for (const file of files) {
      const content = readFileSync(file, 'utf8');
      for (const match of content.matchAll(/\\?"(?:payment_preimage|r_preimage|preimage)\\?"\s*:\s*\\?"([^"\\]*)\\?"/g)) preimages.push(match[1] ?? '');
      for (const sentinel of readdirSync(join(repoRoot, 'test', 'sentinels'))) {
        for (const [encoding, form] of secretForms(readFileSync(join(repoRoot, 'test', 'sentinels', sentinel)))) expect(content.includes(form), `${relative(repoRoot, file)} holds ${sentinel} as ${encoding}`).toBe(false);
      }
    }
    // The succeeded track stream and the settled sendpays carry a real preimage, so fingerprints must appear.
    expect(preimages.some(value => /^fp:[0-9a-f]{16}$/.test(value))).toBe(true);
    for (const value of preimages) expect(/^fp:[0-9a-f]{16}$/.test(value) || /^0{64}$/.test(value) || value === '' || value === 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', `preimage value ${value.slice(0, 8)}…`).toBe(true);
  });
});

describe('recordings tool', () => {
  const sentinel = (name: string): Buffer => readFileSync(join(repoRoot, 'test', 'sentinels', name));
  const fp = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex').slice(0, 16);

  it('CP-009/B3 redaction fingerprints preimage members and removes registered secrets in every encoding', async () => {
    const { redactText } = await tool();
    const preimage = sentinel('preimage.bin'), macaroon = sentinel('macaroon.bin'), rune = sentinel('rune.txt');
    const other = Buffer.alloc(32, 7); // a node-made preimage the tool never registered
    const raw = `{"result":{"payment_preimage":"${preimage.toString('hex')}","htlcs":[{"preimage":"${preimage.toString('base64')}"}],` +
      `"r_preimage":"${other.toString('base64')}","zero":{"payment_preimage":"${'0'.repeat(64)}"},` +
      `"note":"mac ${macaroon.toString('hex').toUpperCase()} url ${macaroon.toString('base64url')} rune ${rune.toString('utf8')}","max_pending_amt_msat":18446744073709551615}}`;
    const redacted = redactText(raw, [preimage, macaroon, rune]);
    expect(redacted).toBe(`{"result":{"payment_preimage":"fp:${fp(preimage)}","htlcs":[{"preimage":"fp:${fp(preimage)}"}],` +
      `"r_preimage":"fp:${fp(other)}","zero":{"payment_preimage":"${'0'.repeat(64)}"},` +
      `"note":"mac [redacted fp:${fp(macaroon)}] url [redacted fp:${fp(macaroon)}] rune [redacted fp:${fp(rune)}]","max_pending_amt_msat":18446744073709551615}}`);
    for (const secret of [preimage, macaroon, rune, other]) for (const [encoding, form] of secretForms(secret)) expect(redacted.includes(form), encoding).toBe(false);
  });

  // B4: guards on GetInfo/getinfo only (INV-15); nothing is created on refusal.
  async function refused(answers: { lnd: Record<string, unknown>; cln: Record<string, unknown> }): Promise<{ code: number; calls: string[]; execs: number; out: string }> {
    const root = scratchDir('cp009-guard-');
    const runtimeRoot = join(root, 'runtime'), sentinelRoot = join(root, 'sentinels');
    mkdirSync(runtimeRoot); mkdirSync(sentinelRoot);
    const owner = join(root, 'owner.json'), out = join(root, 'out');
    writeFileSync(owner, JSON.stringify({ version: 1, id: 'guard', project: 'fluxwarden-lab-guard', runtimeRoot, tmpRoot: join(root, 'tmp'), sentinelRoot, evidenceRoot: join(root, 'evidence'), ports: { lndRest: 28480, clnRest: 28481, toxiproxy: 28482 } }));
    writeFileSync(join(runtimeRoot, 'lab.json'), JSON.stringify({ version: 1, project: 'fluxwarden-lab-guard', ports: { lndRest: 28480, clnRest: 28481, toxiproxy: 28482 }, nodes: {}, credentials: {} }));
    const calls: string[] = [];
    let execs = 0;
    const transport: Transport = request => {
      calls.push(`${request.node} ${request.method} ${request.path}`);
      if (request.path === '/v1/getinfo') return Promise.resolve(request.node === 'lnd-r' ? { status: 200, body: JSON.stringify(answers.lnd) } : { status: 201, body: JSON.stringify(answers.cln) });
      return Promise.resolve({ status: 200, body: '{}' });
    };
    const exec: Exec = () => { execs += 1; return Promise.resolve({ exitCode: 0, stdout: '{}', stderr: '' }); };
    const code = await (await tool()).main(['--owner', owner, '--out', out], { transport, exec });
    return { code, calls, execs, out };
  }
  const lnd = (network: string, version: string): Record<string, unknown> => ({ identity_pubkey: `03${'b2'.repeat(32)}`, version, chains: [{ chain: 'bitcoin', network }], synced_to_chain: true, block_height: 113 });
  const cln = (network: string, version: string): Record<string, unknown> => ({ id: `02${'e5'.repeat(32)}`, version, network, blockheight: 113 });

  it.each([
    ['LND on signet', lnd('signet', '0.21.4-beta commit=v0.21.4-beta'), cln('regtest', 'v26.06.9')],
    ['LND at 0.20.1-beta', lnd('regtest', '0.20.1-beta commit=v0.20.1-beta'), cln('regtest', 'v26.06.9')],
    ['CLN on testnet4', lnd('regtest', '0.21.4-beta commit=v0.21.4-beta'), cln('testnet4', 'v26.06.9')],
    ['CLN at v26.04.1', lnd('regtest', '0.21.4-beta commit=v0.21.4-beta'), cln('regtest', 'v26.04.1')],
  ])('CP-009/B4 %s exits 1 after identity calls only and writes nothing', async (_name, lndInfo, clnInfo) => {
    const result = await refused({ lnd: lndInfo, cln: clnInfo });
    expect(result.code).toBe(1);
    expect(result.calls.length).toBeGreaterThan(0);
    expect(result.calls.every(call => call.endsWith(' /v1/getinfo'))).toBe(true);
    expect(result.execs).toBe(0);
    expect(existsSync(result.out)).toBe(false);
  });

  it('CP-009/B4 a pinned regtest pair passes the guards and goes on to record', async () => {
    const result = await refused({ lnd: lnd('regtest', '0.21.4-beta commit=v0.21.4-beta'), cln: cln('regtest', 'v26.06.9') });
    // The stub answers everything else with {}, so recording itself fails, but only after the guards.
    expect(result.calls.some(call => !call.endsWith(' /v1/getinfo'))).toBe(true);
    expect(result.code).toBe(1);
    expect(existsSync(result.out) ? filesUnder(result.out) : []).toEqual([]);
  });
});
