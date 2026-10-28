import { writeFile, appendFile, lstat, unlink } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createLab } from './lab.mjs';
import { validateOwner, protectCreated } from './owner.mjs';
import { validateCredentialPolicy } from './credentials.mjs';
import { createCredentialPermissions } from './credential-permissions.mjs';
import { composeEnvironment, runDocker } from './compose.mjs';
import { assertPrivateDirectories } from '../../scripts/private-scratch.mjs';
import { readCurrentBinding, assertCurrentBinding } from '../scenarios/live-profile.mjs';

const methods = ['getinfo', 'listpeerchannels', 'listsendpays', 'listpays', 'listinvoices', 'bkpr-listaccountevents', 'askrene-listlayers'];
const fail = () => new Error('lab reference read: failed');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const absolute = path => typeof path === 'string' && isAbsolute(path) && resolve(path) === path;
const within = (root, path) => { const part = relative(root, path); return part && !part.startsWith('..') && !isAbsolute(part); };
const privateIO = root => createCredentialPermissions({ runtimeRoot: root, tmpRoot: root, sentinelRoot: root });

/** Separate observation authority; never enters the normal role manifest or application config. */
export async function produceReferenceRead({ ownerPath, sourceCommit, adapterPath, signal }) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
  const cancellation = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  const deadline = performance.now() + 30000;
  let owner, containerId, uniqueId;
  const guard = () => { if (cancellation.aborted || performance.now() >= deadline) throw fail(); };
  const cli = async (args, cleanup = false) => {
    if (!cleanup) guard();
    const answer = await runDocker(['--config', owner.project, 'exec', containerId, 'lightning-cli', '--network=regtest', '-k', ...args],
      { cwd: owner.runtimeRoot, env: composeEnvironment(owner), timeoutMs: cleanup ? 30000 : Math.max(1, Math.min(30000, deadline - performance.now())), ...(cleanup ? {} : { signal: cancellation }) });
    if (answer.exitCode !== 0 || Buffer.byteLength(answer.stdout) > 65536 || Buffer.byteLength(answer.stderr) > 65536) throw fail();
    if (!cleanup) guard();
    return answer.stdout;
  };
  try {
    guard();
    const globalRoot = process.env.FLUXWARDEN_SENTINEL_DIR, testTmp = process.env.FLUXWARDEN_TEST_TMP;
    if (!absolute(ownerPath) || !absolute(adapterPath) || !absolute(globalRoot) || !absolute(testTmp) || !/^[a-f0-9]{40}$/.test(sourceCommit)) throw fail();
    owner = validateOwner(JSON.parse(Buffer.from(await privateIO(dirname(ownerPath)).readChecked(ownerPath)).toString('utf8')));
    const policy = validateCredentialPolicy(owner.credentialPolicy), permissions = createCredentialPermissions(owner);
    await assertPrivateDirectories([owner.runtimeRoot, owner.tmpRoot, owner.sentinelRoot, owner.evidenceRoot, globalRoot, testTmp]);
    const binding = readCurrentBinding(ownerPath, sourceCommit);
    const manifest = JSON.parse(Buffer.from(await permissions.readChecked(join(owner.runtimeRoot, 'lab.json'))).toString('utf8'));
    const adapter = JSON.parse(Buffer.from(await privateIO(dirname(adapterPath)).readChecked(adapterPath)).toString('utf8'));
    const endpoint = adapter.cln, node = manifest.nodes['cln-m'];
    if (adapter.version !== 1 || adapter.network !== 'regtest' || adapter.disposable !== true || adapter.project !== owner.project
      || endpoint.service !== 'cln-m' || endpoint.host !== 'localhost' || endpoint.port !== owner.ports.clnRest
      || endpoint.pubkey !== node.pubkey || endpoint.tlsCert !== node.certificate.path || !within(owner.runtimeRoot, endpoint.tlsCert)
      || endpoint.rune !== manifest.credentials['cln-m'].execute.path) throw fail();
    if (digest(await permissions.readChecked(endpoint.tlsCert)) !== node.certificate.sha256) throw fail();
    const observed = await createLab({ owner, signal: cancellation }).observe();
    containerId = observed.resources.find(value => value.service === 'cln-m')?.containerId;
    if (typeof containerId !== 'string' || !/^[a-f0-9]{64}$/.test(containerId)) throw fail();
    assertCurrentBinding(binding, ownerPath, sourceCommit);
    await permissions.ensureDirectory(join(owner.runtimeRoot, 'reference'));
    const path = join(owner.runtimeRoot, 'reference', 'cln-m-cp012-read.rune');
    const ownerSource = join(owner.sentinelRoot, `reference-read-${randomUUID()}.bin`), globalSource = join(globalRoot, `reference-read-${randomUUID()}.bin`);
    for (const target of [path, ownerSource, globalSource]) {
      try { await lstat(target); throw fail(); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    // Canonical credential/source destinations are declared before their first write.
    // The separate metadata record is ordinary retained output, never an input exemption.
    await appendFile(join(testTmp, 'declared-out.txt'), [path, ownerSource, globalSource].map(value => `${value}\n`).join(''), { mode: 0o600 });
    const minted = JSON.parse(await cli(['createrune', `restrictions=${JSON.stringify([methods.map(method => `method=${method}`), [`rate=${policy.callsPerMinute}`]])}`]));
    if (typeof minted.unique_id !== 'string' || !/^(0|[1-9][0-9]*)$/.test(minted.unique_id) || typeof minted.rune !== 'string' || !/^[A-Za-z0-9_+/-]+={0,2}$/.test(minted.rune)) throw fail();
    uniqueId = minted.unique_id;
    const bytes = Buffer.from(minted.rune);
    // ccan/rune/coding.c: the authenticated text follows the 32-byte authenticator.
    const decoded = Buffer.from(minted.rune, 'base64url').subarray(32).toString('utf8');
    if (decoded !== `=${uniqueId}&${methods.map(method => `method=${method}`).join('|')}&rate=${policy.callsPerMinute}`) throw fail();
    for (const role of ['read', 'execute']) if (Buffer.from(await permissions.readChecked(manifest.credentials['cln-m'][role].path)).equals(bytes)) throw fail();
    await permissions.writeExclusive(ownerSource, bytes);
    await privateIO(globalRoot).writeExclusive(globalSource, bytes);
    await permissions.writeExclusive(path, bytes);
    if (![await permissions.readChecked(path), await permissions.readChecked(ownerSource), await privateIO(globalRoot).readChecked(globalSource)].every(value => Buffer.from(value).equals(bytes))) throw fail();
    guard(); assertCurrentBinding(binding, ownerPath, sourceCommit);
    const record = { version: 1, purpose: 'cp012-reference-read-only', binding,
      endpoint: { service: 'cln-m', host: endpoint.host, port: endpoint.port, pubkey: endpoint.pubkey, tlsCert: endpoint.tlsCert, tlsSha256: node.certificate.sha256 },
      credential: { path, sha256: digest(bytes), fingerprint: `fp:${digest(bytes).slice(0, 16)}`, uniqueId }, methods: [...methods], ratePerMinute: policy.callsPerMinute };
    const recordPath = join(owner.evidenceRoot, 'cp012-reference-authority.json');
    let previousFile;
    try { previousFile = await lstat(recordPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (previousFile) {
      const previous = JSON.parse(Buffer.from(await privateIO(owner.evidenceRoot).readChecked(recordPath)).toString('utf8'));
      if (previous.purpose !== record.purpose || previous.binding?.ownerPath !== ownerPath || previous.binding?.ownerId !== owner.id || previous.binding?.project !== owner.project) throw fail();
      await unlink(recordPath);
    }
    await writeFile(recordPath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await protectCreated([recordPath], { privateDirectories: [owner.evidenceRoot] });
    guard(); assertCurrentBinding(binding, ownerPath, sourceCommit);
    return { path: recordPath };
  } catch {
    if (uniqueId && containerId) { try { await cli(['blacklistrune', `start=${uniqueId}`, `end=${uniqueId}`], true); } catch { /* ordinary owner teardown remains required */ } }
    throw fail();
  } finally { clearTimeout(timer); }
}
