// Native CLN-only T-25 stimulus. No Docker work happens on import.
// Bitcoin v31.1 src/rpc/mining.cpp:281-378 generateblock submit=false,
// 1022-1057 submitheader, 973-1019 submitblock.
// CLN v26.06.9 lightningd/chaintopology.c:1229-1257 rejects headers!=blocks;
// peer_control.c:3376-3381 exposes warning_bitcoind_sync in actual getinfo.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { qualifyNativeReference, qualifyReference, referenceServices } from './owned-reference.mjs';

class NativeLabInvalidError extends Error {
  constructor(reason) { super(`LabInvalidError: T-25 ${reason}`); this.name = 'LabInvalidError'; }
}
const invalid = reason => new NativeLabInvalidError(reason);
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const row = value => value && typeof value === 'object' && !Array.isArray(value) ? value : (() => { throw invalid('native object missing'); })();

export async function withWithheldBlock({ owner, manifest, body, retain, persistBlock,
  run = spawnSync, now = Date.now, pause = ms => delay(ms) }) {
  // These are the original live-reference command and polling bounds.
  const command = (args, optionalNull = false, timeout = 30_000) => {
    const result = run('docker', args, { encoding: 'utf8', shell: false, windowsHide: true, timeout, maxBuffer: 1024 * 1024 });
    if (result.status !== 0) throw invalid('owned command failed');
    const text = result.stdout.trim();
    if (optionalNull === 'text') return text;
    if (optionalNull && text === '') return null;
    try { return JSON.parse(text); } catch { throw invalid('native JSON missing'); }
  };
  const bitcoin = (method, args = [], optionalNull = false) => command(['exec', `${owner.project}-bitcoind-1`, 'bitcoin-cli', '-regtest', method, ...args], optionalNull);
  const info = (node, timeout = 30_000) => row(command(['exec', `${owner.project}-${node}-1`,
    ...(node.startsWith('lnd-') ? ['lncli', '--network=regtest'] : ['lightning-cli', '--network=regtest', '-k']), 'getinfo'], false, timeout));
  const identity = (node, value) => {
    const lnd = node.startsWith('lnd-'), expected = manifest.nodes?.[node];
    if (!expected || (lnd ? value.identity_pubkey : value.id) !== expected.pubkey ||
        (lnd ? value.chains?.length !== 1 || value.chains[0]?.network !== 'regtest' || value.chains[0]?.chain !== 'bitcoin' : value.network !== 'regtest') ||
        (lnd ? !/^0\.21\.4-beta(?: commit=v0\.21\.4-beta)?$/.test(value.version) : value.version !== 'v26.06.9')) throw invalid('native pin mismatch');
    return value;
  };
  const wait = async (observe, milliseconds, label) => {
    const deadline = now() + milliseconds;
    for (;;) {
      if (now() >= deadline) throw invalid(`${label} unavailable within original bound`);
      try { const result = observe(Math.max(1, Math.min(3000, deadline - now()))); if (result) return result; }
      catch (error) { if (!(error instanceof Error) || !error.message.includes('owned command failed')) throw error; }
      await pause(Math.min(200, Math.max(1, deadline - now())));
    }
  };
  const chain = () => {
    const value = row(bitcoin('getblockchaininfo'));
    if (value.chain !== 'regtest' || !Number.isSafeInteger(value.blocks) || !Number.isSafeInteger(value.headers)) throw invalid('owned chain mismatch');
    return value;
  };
  qualifyReference(owner, manifest);
  qualifyNativeReference(owner, manifest, command(['inspect', ...referenceServices.map(service => `${owner.project}-${service}-1`)]));
  const before = chain();
  if (before.headers !== before.blocks) throw invalid('pre-existing header gap');
  // A no-transaction, one-coinbase block. raw(51) is a public OP_TRUE descriptor,
  // not a private key or a new node credential. No block is connected yet.
  const generated = row(bitcoin('generateblock', ['raw(51)', '[]', 'false']));
  if (typeof generated.hex !== 'string' || !/^[a-f0-9]+$/.test(generated.hex) || generated.hex.length < 162 || generated.hex.length > 131072 ||
      typeof generated.hash !== 'string' || !/^[a-f0-9]{64}$/.test(generated.hash)) throw invalid('bounded one-block fixture missing');
  const header = generated.hex.slice(0, 160), bytes = Buffer.from(header, 'hex');
  if (sha256(sha256(bytes)).reverse().toString('hex') !== generated.hash || bytes.subarray(4, 36).reverse().toString('hex') !== before.bestblockhash)
    throw invalid('generated block does not extend owned tip');
  const prepared = chain();
  if (prepared.blocks !== before.blocks || prepared.bestblockhash !== before.bestblockhash) throw invalid('block connected before stimulus');
  // Caller persists this exact public block under its existing protected tmp
  // root before admitting a header, so interruption recovery has the body.
  persistBlock(generated);
  let attemptedHeader = false;
  const restore = async () => {
    if (attemptedHeader) {
      const submitted = bitcoin('submitblock', [generated.hex], true);
      if (submitted !== null && submitted !== 'duplicate') throw invalid('withheld body was not accepted');
      const restored = chain();
      if (restored.blocks !== before.blocks + 1 || restored.headers !== restored.blocks || restored.bestblockhash !== generated.hash) throw invalid('one-block recovery not observed');
      await wait(timeout => {
        const nodes = referenceServices.filter(node => node !== 'bitcoind' && node !== 'toxiproxy');
        const facts = nodes.map(node => ({ node, info: identity(node, info(node, timeout)) }));
        const synced = facts.every(({ node, info: value }) => Number(node.startsWith('lnd-') ? value.block_height : value.blockheight) === restored.blocks &&
          (node.startsWith('lnd-') ? value.synced_to_chain === true : value.warning_bitcoind_sync === undefined && value.warning_lightningd_sync === undefined));
        if (synced) retain('t25-cln-restored-all-native-nodes', { chain: restored, nodes: facts });
        return synced;
      }, 30_000, 'all owned native nodes synced');
    }
  };

  try {
    attemptedHeader = true;
    bitcoin('submitheader', [header], true);
    const held = chain();
    retain('t25-cln-withheld-header', { before, held, generatedHash: generated.hash, blockBytes: generated.hex.length / 2 });
    if (held.blocks !== before.blocks || held.headers !== before.blocks + 1 || held.bestblockhash !== before.bestblockhash) throw invalid('single withheld header not observed');
    command(['restart', `${owner.project}-cln-m-1`], 'text');
    const unsynced = await wait(timeout => {
      const value = identity('cln-m', info('cln-m', timeout));
      return typeof value.warning_bitcoind_sync === 'string' && value.warning_bitcoind_sync.length > 0 ? value : null;
    }, 20_000, 'native CLN backend-sync warning');
    retain('t25-cln-unsynced-before-execute', unsynced);
    const result = await body();
    const after = identity('cln-m', info('cln-m'));
    retain('t25-cln-unsynced-after-execute', after);
    if (typeof after.warning_bitcoind_sync !== 'string' || after.warning_bitcoind_sync.length === 0) throw invalid('native CLN warning disappeared during execute');
    const stillHeld = chain();
    if (stillHeld.blocks !== before.blocks || stillHeld.headers !== before.blocks + 1) throw invalid('stimulus changed during execute');
    return result;
  } finally { await restore(); }
}
