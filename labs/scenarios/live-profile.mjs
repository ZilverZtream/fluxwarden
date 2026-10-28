// Independent live-profile producers. Importing this file performs no work.
// Native answers, retained originals and completed subprocesses are evidence;
// arithmetic and requested outcome names never stand in for native observations.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

const nodes = ['lnd-p', 'lnd-r', 'cln-p', 'cln-r', 'cln-m'];
const services = ['bitcoind', ...nodes, 'toxiproxy'];
const limitMs = 180000;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const invalid = reason => new Error(`LabInvalidError: ${reason}`);
// Same explicit process-host boundary as chaos/live-reference.mjs. The public
// scripts hook supplies spawnSync; scenario imports themselves start nothing.
let runner;
export function setRunner(value) { runner = value; }
function requireFact(condition, reason) { if (!condition) throw invalid(reason); }
function object(value) { requireFact(value && typeof value === 'object' && !Array.isArray(value), 'observed object required'); return value; }
function bytes(file) {
  requireFact(isAbsolute(file) && realpathSync(file) === resolve(file) && lstatSync(file).isFile() && !lstatSync(file).isSymbolicLink(), 'canonical ordinary input required');
  requireFact(lstatSync(file).size <= 16 * 1024 * 1024, 'input exceeds bounded size'); return readFileSync(file);
}
function json(file) { return object(JSON.parse(bytes(file).toString('utf8'))); }
function inside(root, file) { const part = relative(root, file); return part !== '' && part !== '..' && !part.startsWith(`..${sep}`) && !isAbsolute(part); }
function directory(path) { requireFact(isAbsolute(path) && realpathSync(path) === resolve(path) && lstatSync(path).isDirectory() && !lstatSync(path).isSymbolicLink(), 'canonical owned directory required'); return path; }
function write(file, value) { writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' }); return file; }
function child(root, prefix) { return mkdtempSync(join(directory(root), prefix)); }
function decimal(value) { const text = String(value).replace(/msat$/, ''); requireFact(/^(0|[1-9][0-9]*)$/.test(text), 'native decimal amount required'); return BigInt(text); }

/** Byte identity changes on every ordinary startup, including randomized credentials. */
export function readCurrentBinding(ownerPath, sourceCommit) {
  requireFact(/^[a-f0-9]{40}$/.test(sourceCommit), 'complete source commit required');
  const ownerBytes = bytes(ownerPath), owner = object(JSON.parse(ownerBytes.toString('utf8')));
  requireFact(/^[a-z0-9-]+$/.test(owner.id) && /^fluxwarden-lab-[a-z0-9-]+$/.test(owner.project), 'explicit current owner required');
  for (const root of ['runtimeRoot', 'tmpRoot', 'evidenceRoot', 'sentinelRoot']) directory(owner[root]);
  const manifestBytes = bytes(join(owner.runtimeRoot, 'lab.json')), manifest = object(JSON.parse(manifestBytes.toString('utf8')));
  requireFact(manifest.ownerId === owner.id && manifest.project === owner.project && independentPolicyJson(manifest.ports) === independentPolicyJson(owner.ports), 'runtime does not belong to declared owner');
  for (const node of nodes) {
    const entry = manifest.nodes?.[node];
    requireFact(entry?.network === 'regtest' && /^(02|03)[a-f0-9]{64}$/.test(entry.pubkey), 'current regtest identity unavailable');
    requireFact(node.startsWith('lnd-') ? /^0\.21\.4-beta(?: |$)/.test(entry.version) : entry.version === 'v26.06.9', 'pinned node version required');
  }
  return { version: 1, sourceCommit, ownerPath, ownerSha256: hash(ownerBytes), ownerId: owner.id, project: owner.project, manifestSha256: hash(manifestBytes) };
}
export function assertCurrentBinding(binding, ownerPath, sourceCommit) {
  requireFact(independentPolicyJson(binding) === independentPolicyJson(readCurrentBinding(ownerPath, sourceCommit)), 'stale source, owner or startup manifest');
}

/** SPEC policy JSON: sorted object keys, integer numbers, decimal amount strings. */
export function independentPolicyJson(value) {
  if (Array.isArray(value)) return `[${value.map(independentPolicyJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${independentPolicyJson(value[key])}`).join(',')}}`;
  requireFact(typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value)), 'unsupported independent policy value');
  return JSON.stringify(value);
}
export function independentPolicyHash(value) { return hash(independentPolicyJson(value)); }

/** Pinned Vitest5 JSON reporter and dynamic-list protocol, independently read
 * from its primary package. Never split opaque names: titles may contain >.
 * Empty ancestor names remain in JSON fullName but getNames omits them in list.
 */
export function reportedCaseName(assertion) {
  const result = object(assertion), safe = value => typeof value === 'string' && [...value].every(character => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127);
  requireFact(Array.isArray(result.ancestorTitles) && result.ancestorTitles.every(safe) && safe(result.title) && safe(result.fullName), 'original reporter structure required');
  const fullName = result.title ? [...result.ancestorTitles, result.title].join(' ') : result.ancestorTitles.join(' ');
  requireFact(result.fullName === fullName, 'original fullName disagrees with reporter structure');
  return [...result.ancestorTitles.filter(title => title !== ''), result.title].join(' > ');
}

function nativeRunner(owner) {
  requireFact(typeof runner === 'function', 'public process runner required');
  const containers = new Map();
  return (service, args) => {
    requireFact(services.includes(service), 'owned service required');
    if (!containers.has(service)) {
      const found = runner('docker', ['ps', '-q', '--filter', `label=com.docker.compose.project=${owner.project}`, '--filter', `label=com.docker.compose.service=${service}`], { encoding: 'utf8', shell: false, windowsHide: true, timeout: 30000 });
      const ids = found.status === 0 ? found.stdout.trim().split(/\s+/).filter(Boolean) : [];
      requireFact(ids.length === 1, 'exactly one owned native service required'); containers.set(service, ids[0]);
    }
    const cli = service === 'bitcoind' ? ['bitcoin-cli', '-regtest'] : service.startsWith('lnd-') ? ['lncli', '--network=regtest'] : ['lightning-cli', '--network=regtest', '-k'];
    const result = runner('docker', ['exec', containers.get(service), ...cli, ...args], { encoding: 'utf8', shell: false, windowsHide: true, timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
    return { exitCode: result.error ? null : result.status, stdout: result.stdout, stderr: result.stderr };
  };
}
function oracle(native, service, args) {
  const result = native(service, args);
  requireFact(result.exitCode === 0, 'native command did not complete successfully');
  const stdout = result.stdout.split('\n').filter(line => !line.startsWith('# ')).join('\n');
  return JSON.parse(stdout);
}
function route(channel, pubkey, amount, height) {
  // Exact original CP010 oneHopRoute envelope, including its unknown MPP address.
  return JSON.stringify({ route: { total_time_lock: height + 100, total_amt_msat: amount.toString(), hops: [{ chan_id: channel, expiry: height + 100, amt_to_forward_msat: amount.toString(), fee_msat: '0', pub_key: pubkey, tlv_payload: true, mpp_record: { payment_addr: randomBytes(32).toString('hex'), total_amt_msat: amount.toString() } }] } });
}

/** Only the pinned remote unknown-hash failure proves first-hop acceptance. */
export function classifyFirstHop(attempt) {
  requireFact(attempt?.status === 'FAILED', 'unknown-hash probe did not fail');
  if (attempt.failure?.failure_source_index === 1 && attempt.failure.code === 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS') return 'accepted';
  if (attempt.failure?.failure_source_index === 0 && typeof attempt.failure.code === 'string') return 'refused';
  throw invalid('unrecognized native first-hop outcome');
}

export function capturePlanner({ ownerPath, sourceCommit, evidenceRoot, native }) {
  const binding = readCurrentBinding(ownerPath, sourceCommit), owner = json(ownerPath), manifest = json(join(owner.runtimeRoot, 'lab.json'));
  native ??= nativeRunner(owner);
  const root = child(evidenceRoot ?? owner.evidenceRoot, 'planner-'), startedAt = Date.now(), observations = [], referenceConflicts = [];
  const deadline = () => requireFact(Date.now() - startedAt <= limitMs, 'planner capture deadline exceeded');
  const height = Number(oracle(native, 'bitcoind', ['getblockcount'])); requireFact(Number.isSafeInteger(height) && height > 0, 'native height required');
  const captures = {};
  for (const [node, method] of [['lnd-r', 'listchannels'], ['cln-m', 'listpeerchannels']]) {
    const info = object(oracle(native, node, ['getinfo'])), channels = object(oracle(native, node, [method]));
    requireFact((node === 'lnd-r' ? info.block_height : info.blockheight) === height && (node === 'lnd-r' ? info.identity_pubkey : info.id) === manifest.nodes[node].pubkey, 'native capture identity or height mismatch');
    requireFact(Array.isArray(channels.channels) && channels.channels.length > 0 && channels.channels.every(c => !(c.pending_htlcs ?? c.htlcs ?? []).length), 'nonempty idle native channels required');
    mkdirSync(join(root, node), { mode: 0o700 }); write(join(root, node, 'getinfo.json'), info); write(join(root, node, `${method}.json`), channels); captures[node] = channels;
  }
  const probes = [];
  for (const channel of captures['lnd-r'].channels) {
    // Pinned lncli exposes the decimal short ID as scid and the 32-byte ID as chan_id.
    const chanId = String(channel.scid ?? channel.chan_id), pubkey = channel.remote_pubkey;
    requireFact(/^[0-9]+$/.test(chanId) && Object.values(manifest.nodes).some(n => n.pubkey === pubkey), 'owned native first hop required');
    const probe = amount => {
      deadline();
      const attempt = object(oracle(native, 'lnd-r', ['sendtoroute', '--payment_hash', randomBytes(32).toString('hex'), '--routes', route(chanId, pubkey, amount, height)]));
      const outcome = classifyFirstHop(attempt);
      observations.push({ chan_id: chanId, amount_msat: amount.toString(), status: attempt.status, failure: { code: attempt.failure.code, failure_source_index: attempt.failure.failure_source_index }, outcome });
      return outcome === 'accepted';
    };
    // CP010 RA2 / ARCHITECTURE 4.1 arithmetic chooses probe inputs only.
    const local = decimal(channel.local_balance), reserve = decimal(channel.local_constraints.chan_reserve_sat);
    const buffer = channel.initiator === true ? 2n * decimal(channel.fee_per_kw) * (decimal(channel.commit_weight) + 172n) / 1000n + 660n : 0n;
    const derived = (local - reserve - buffer) * 1000n; requireFact(derived > 0n, 'positive conservative probe input required');
    const acceptsDerived = probe(derived); probe(derived + 1n);
    if (!acceptsDerived) throw new Error('REFERENCE_CONFLICT CP-014/R2 declared conservative spendable refused');
    let low = derived, high = local * 1000n + 1n;
    requireFact(!probe(high), 'native probe bracket unavailable');
    while (high - low > 1n) { const middle = (low + high) / 2n; if (probe(middle)) low = middle; else high = middle; }
    requireFact(probe(low) && !probe(high), 'native adjacent boundary did not reproduce');
    probes.push({ chan_id: chanId, accepted_msat: low.toString(), refused_msat: high.toString() });
    // D29 conservative-spendable reference resolution: +1 acceptance is a
    // diagnostic, not a conflict. The actual declared-amount probe above remains mandatory.
    if (derived > low) referenceConflicts.push({ status: 'REFERENCE_CONFLICT', caseId: 'CP-014/R2', chan_id: chanId, derived_msat: derived.toString(), accepted_msat: low.toString(), refused_msat: high.toString() });
  }
  requireFact(Number(oracle(native, 'bitcoind', ['getblockcount'])) === height, 'height changed during captures and probes'); deadline(); assertCurrentBinding(binding, ownerPath, sourceCommit);
  write(join(root, 'lnd-r', 'spendable-probe.json'), probes);
  const names = ['lnd-r/getinfo.json', 'lnd-r/listchannels.json', 'cln-m/getinfo.json', 'cln-m/listpeerchannels.json', 'lnd-r/spendable-probe.json'];
  const artifacts = names.map(file => ({ file, sha256: hash(readFileSync(join(root, file))) }));
  const receiptPath = write(join(root, 'capture-receipt.json'), { binding, startedAt, finishedAt: Date.now(), height, observations, referenceConflicts, artifacts });
  return { captureDir: root, receiptPath, referenceConflicts };
}

export function assertPlannerCapture(captureDir, ownerPath, sourceCommit) {
  const receipt = json(join(captureDir, 'capture-receipt.json')); assertCurrentBinding(receipt.binding, ownerPath, sourceCommit);
  requireFact(receipt.artifacts?.length === 5, 'all five current native capture artifacts required');
  for (const artifact of receipt.artifacts) {
    const file = resolve(captureDir, artifact.file); requireFact(inside(captureDir, file) && hash(bytes(file)) === artifact.sha256, 'native capture artifact hash mismatch');
  }
  return receipt;
}

/** Preserve original bytes before ordinary down clears runtimeRoot. */
export function retainDemoHandoff({ ownerPath, sourceCommit, bundle, actualT05Path, nativeHistoryPath, verificationPath, evidenceRoot }) {
  const binding = readCurrentBinding(ownerPath, sourceCommit), owner = json(ownerPath), root = child(evidenceRoot ?? owner.evidenceRoot, 'demo-handoff-');
  requireFact(inside(owner.evidenceRoot, root), 'demo handoff must remain under owner evidence');
  const runtimeManifest = { file: join(root, 'lab.json'), sha256: binding.manifestSha256 };
  copyFileSync(join(owner.runtimeRoot, 'lab.json'), runtimeManifest.file);
  // Original evidence paths remain original. No native facts are synthesized here.
  directory(bundle); bytes(actualT05Path); bytes(nativeHistoryPath); bytes(verificationPath);
  const handoffPath = write(join(root, 'handoff.json'), { owner: ownerPath, bundle, actualT05Path, nativeHistoryPath, verificationPath, binding, runtimeManifest });
  return { handoffPath, runtimeManifest };
}

/** Read-only artifact consumer; deliberately independent of the live runtime path. */
export function readRetainedDemoRuntime(handoff) {
  const owner = json(handoff.owner), binding = object(handoff.binding), retained = object(handoff.runtimeManifest);
  requireFact(/^[a-f0-9]{40}$/.test(binding.sourceCommit), 'retained source binding required');
  requireFact(hash(bytes(handoff.owner)) === binding.ownerSha256 && owner.id === binding.ownerId && owner.project === binding.project, 'retained owner binding mismatch');
  requireFact(retained.sha256 === binding.manifestSha256 && hash(bytes(retained.file)) === retained.sha256, 'retained runtime manifest hash mismatch');
  requireFact(inside(owner.evidenceRoot, retained.file), 'retained runtime manifest must belong to owner evidence');
  const runtime = json(retained.file);
  requireFact(runtime.ownerId === owner.id && runtime.project === owner.project && independentPolicyJson(runtime.ports) === independentPolicyJson(owner.ports), 'retained runtime belongs to another owner');
  return { owner, runtime };
}

/** SPEC 7.1 frozen caps, with the walkthrough's explicitly established 1s cooldown. */
export function frozenChaosPolicy(targets) {
  return { version: 3, network: 'regtest', fees: { max_fee_msat: '300000', max_fee_ppm: 2500, exempt_fee_msat: '5000' }, routing: { max_cltv_delta: 144 },
    amounts: { min_channel_reserve_msat: '50000000', max_principal_msat: '100000000', min_principal_msat: '10000000' }, budget: { msat: '2000000', period: 86400 },
    cooldown_after_failure: 3600, cooldown_after_success: 1, max_in_flight: 1, max_snapshot_age: 60, proposal_ttl: 900, approval_max_ttl: 900,
    demand: { mode: 'targets', horizon: 21600, burst_factor: '1.4', ewma: { bucket_seconds: 3600, alpha: '0.35', min_samples: 12 } }, targets, exclude_channels: [] };
}
const durationFields = new Set(['period', 'cooldown_after_failure', 'cooldown_after_success', 'max_snapshot_age', 'proposal_ttl', 'approval_max_ttl', 'horizon']);
function policyYaml(value, indent = '') {
  return Object.entries(value).map(([key, item]) => {
    const head = `${indent}${JSON.stringify(key)}:`;
    if (Array.isArray(item)) { requireFact(item.length === 0, 'only empty excluded-channel sequence emitted'); return ''; }
    if (item && typeof item === 'object') return `${head}\n${policyYaml(item, `${indent}  `)}`;
    return `${head} ${durationFields.has(key) ? `${item}s` : JSON.stringify(item)}\n`;
  }).join('');
}
function cliCommand(sourceRoot, args) {
  requireFact(typeof runner === 'function', 'public process runner required');
  const result = runner(process.execPath, [join(sourceRoot, 'dist/cli/bin.js'), '--json', ...args], { cwd: sourceRoot, env: process.env, encoding: 'utf8', shell: false, windowsHide: true, timeout: limitMs, maxBuffer: 16 * 1024 * 1024 });
  requireFact(!result.error && result.status === 0 && result.signal === null, 'public profile CLI failed');
  const document = object(JSON.parse(result.stdout)); requireFact(document.error === null, 'public profile CLI refused'); return object(document.result);
}

export async function prepareChaos({ ownerPath, sourceRoot, sourceCommit, native }) {
  directory(sourceRoot);
  const binding = readCurrentBinding(ownerPath, sourceCommit), owner = json(ownerPath), manifest = json(join(owner.runtimeRoot, 'lab.json'));
  native ??= nativeRunner(owner);
  const tmp = child(owner.tmpRoot, 'chaos-'), evidence = child(owner.evidenceRoot, 'chaos-profile-'), sentinels = owner.sentinelRoot;
  const config = join(tmp, 'fluxwarden.yaml'), policy = join(tmp, 'policy.yaml'), key = join(tmp, 'operator.key'), database = join(tmp, 'state/fluxwarden.db');
  mkdirSync(join(tmp, 'state'), { mode: 0o700 });
  const startedAt = Date.now(), channelReads = [];
  const observe = () => {
    requireFact(Date.now() - startedAt <= limitMs, 'chaos preparation deadline exceeded');
    const info = object(oracle(native, 'cln-m', ['getinfo']));
    requireFact(info.network === 'regtest' && info.version === 'v26.06.9' && info.id === manifest.nodes['cln-m'].pubkey, 'native chaos merchant identity mismatch');
    const channels = object(oracle(native, 'cln-m', ['listpeerchannels'])).channels;
    requireFact(Array.isArray(channels) && channels.every(c => c.state === 'CHANNELD_NORMAL' && !(c.htlcs ?? []).length), 'idle native merchant channels required');
    const source = channels.find(c => c.peer_id === manifest.nodes['lnd-r'].pubkey), target = channels.find(c => c.peer_id === manifest.nodes['cln-r'].pubkey);
    requireFact(source?.short_channel_id && target?.short_channel_id, 'actual merchant source and target channels required');
    channelReads.push(channels); return { source, target };
  };
  let observed = observe(); const before = observed, payments = [];
  while (decimal(observed.source.receivable_msat) > 5000000n) {
    requireFact(payments.length < 50, 'original checkout payment bound exceeded');
    const remaining = decimal(observed.source.receivable_msat) - 5000000n, amount = remaining < 100000000n ? remaining : 100000000n;
    const preimage = randomBytes(32), paymentHash = hash(preimage), secretFile = join(sentinels, `live-profile-preimage-${paymentHash}`);
    writeFileSync(secretFile, preimage, { mode: 0o600, flag: 'wx' }); appendFileSync(join(tmp, 'declared-out.txt'), `${secretFile}\n`);
    const invoice = object(oracle(native, 'cln-m', ['invoice', `amount_msat=${amount}`, `label=profile-${randomUUID()}`, 'description=disposable regtest checkout', 'expiry=300', `preimage=${preimage.toString('hex')}`]));
    requireFact(invoice.payment_hash === paymentHash && typeof invoice.bolt11 === 'string' && invoice.bolt11.startsWith('lnbcrt'), 'native checkout invoice mismatch');
    const paid = object(oracle(native, 'lnd-p', ['payinvoice', '--force', '--json', invoice.bolt11]));
    requireFact(paid.status === 'SUCCEEDED' && paid.payment_hash === paymentHash && decimal(paid.value_msat) === amount && hash(Buffer.from(paid.payment_preimage, 'hex')) === paymentHash, 'native checkout payment not proven');
    const next = observe();
    requireFact(decimal(next.source.receivable_msat) === decimal(observed.source.receivable_msat) - amount && decimal(next.target.receivable_msat) === decimal(before.target.receivable_msat), 'native checkout directional deltas mismatch');
    payments.push({ paymentHash, status: paid.status, amountMsat: amount.toString() }); observed = next;
  }
  requireFact(decimal(observed.target.receivable_msat) >= 100000000n, 'actual target spare capacity below principal');
  const targets = { 'cln-m': { [observed.source.short_channel_id]: { min_inbound_msat: (decimal(observed.source.receivable_msat) + 100000000n).toString() }, [observed.target.short_channel_id]: { min_inbound_msat: '0' } } };
  const policyDocument = frozenChaosPolicy(targets), policySha256 = independentPolicyHash(policyDocument);
  writeFileSync(policy, policyYaml(policyDocument), { mode: 0o600, flag: 'wx' });
  const keyArgs = [join(sourceRoot, 'dist/cli/bin.js'), '--json', 'keys', 'generate', '--out', key];
  if (process.env.FLUXWARDEN_CI_CAPTURE) {
    const { authorizeSecretOutput } = await import('../../scripts/ci-secret-output.mjs');
    await authorizeSecretOutput({ path: key, command: process.execPath, args: keyArgs });
  }
  const publicKey = cliCommand(sourceRoot, ['keys', 'generate', '--out', key]); bytes(key);
  appendFileSync(join(tmp, 'declared-out.txt'), `${key}\n`);
  copyFileSync(key, join(sentinels, `live-profile-operator-${hash(bytes(key))}`));
  const pathText = value => JSON.stringify(value.replaceAll('\\', '/'));
  // Preserve the original scenario helpers' literal database/policy markers.
  const text = `database: ./state/fluxwarden.db\npolicy: ./policy.yaml\ncollect_interval: 15s\nattempt_deadline: 120s\nescalate_after: 1h\napproval_keys:\n  - key_id: ${JSON.stringify(publicKey.key_id)}\n    public_key: ${JSON.stringify(publicKey.public_key)}\nnodes:\n  - name: cln-m\n    implementation: cln\n    url: https://localhost:${owner.ports.clnRest}\n    tls_cert_path: ${pathText(manifest.nodes['cln-m'].certificate.path)}\n    rune_path: ${pathText(manifest.credentials['cln-m'].execute.path)}\n    expected_pubkey: ${JSON.stringify(manifest.nodes['cln-m'].pubkey)}\n    expected_network: regtest\n`;
  writeFileSync(config, text, { mode: 0o600, flag: 'wx' }); cliCommand(sourceRoot, ['doctor', '--config', config]); bytes(database);
  assertCurrentBinding(binding, ownerPath, sourceCommit);
  // Keep required tNN observation files directly in owner.evidenceRoot for sealing.
  const plan = { owner: ownerPath, cwd: sourceRoot, config, database, policy, key, tmp, evidence: owner.evidenceRoot, sentinels, binding, policyDocument, policySha256,
    policyFileSha256: hash(bytes(policy)), configSha256: hash(bytes(config)) };
  write(join(evidence, 'native-preparation.json'), { binding, startedAt, finishedAt: Date.now(), channelReads, payments });
  const planPath = write(join(evidence, 'chaos-plan.json'), plan); return { planPath, policySha256, binding };
}

export function assertChaosPlan(plan) {
  assertCurrentBinding(plan.binding, plan.owner, plan.binding.sourceCommit);
  requireFact(independentPolicyJson(plan.policyDocument) === independentPolicyJson(frozenChaosPolicy(plan.policyDocument.targets)), 'frozen chaos safety cap changed');
  requireFact(plan.policySha256 === independentPolicyHash(plan.policyDocument) && hash(bytes(plan.policy)) === plan.policyFileSha256 && bytes(plan.policy).toString('utf8') === policyYaml(plan.policyDocument), 'independent current chaos policy binding mismatch');
  requireFact(hash(bytes(plan.config)) === plan.configSha256 && existsSync(plan.database), 'current chaos config or initialized database mismatch');
}

/** Capture one real independent invocation; R6 remains the read-only validator. */
export async function measureValidation({ sourceRoot, sourceSha256, invocation, evidenceRoot, selection, collectedAt, commands, env = process.env }) {
  directory(sourceRoot); directory(evidenceRoot);
  requireFact(typeof runner === 'function', 'public process runner required');
  requireFact(/^[a-f0-9]{64}$/.test(sourceSha256) && typeof invocation === 'string' && invocation.length > 0, 'actual source and invocation required');
  requireFact(Array.isArray(selection) && selection.length > 0 && selection.every(c => typeof c.file === 'string' && typeof c.fullName === 'string' && !/CP-006\/R6(?:\s|$)/.test(c.fullName)), 'independent nonempty selection excluding R6 required');
  const selected = selection.map(c => JSON.stringify([relative(sourceRoot, resolve(sourceRoot, c.file)).split(sep).join('/'), c.fullName]));
  requireFact(new Set(selected).size === selected.length && selection.every(c => inside(sourceRoot, resolve(sourceRoot, c.file))), 'unique bounded independent selection required');
  requireFact(Number.isSafeInteger(collectedAt) && collectedAt > 0 && collectedAt <= Date.now(), 'selection must be collected independently before execution');
  const argv = value => { requireFact(Array.isArray(value) && value.length > 0 && value.every(a => typeof a === 'string' && a.length > 0), 'actual nonempty command argv required'); return value; };
  for (const phase of ['build', 'setup', 'teardown', 'leak']) argv(commands[phase]);
  requireFact(Array.isArray(commands.run) && commands.run.length > 0, 'at least one actual selected run required');
  for (const run of commands.run) { argv(run.argv); requireFact(typeof run.report === 'string' && !isAbsolute(run.report) && inside(evidenceRoot, resolve(evidenceRoot, run.report)), 'original report must belong to evidence root'); }
  write(join(evidenceRoot, 'inventory.json'), { invocation, sourceSha256, collectedAt, cases: selection });
  const phases = {}, observed = []; let failure;
  function execute(phase, command, report) {
    const startedAt = Date.now(), result = runner(command[0], command.slice(1), { cwd: sourceRoot, env, encoding: 'utf8', shell: false, windowsHide: true, timeout: limitMs, maxBuffer: 16 * 1024 * 1024 }), finishedAt = Date.now();
    const entry = { phase, startedAt, finishedAt, argv: command, exitCode: result.status, signal: result.signal, ...(report ? { report } : {}) };
    observed.push(entry);
    write(join(evidenceRoot, `command-${observed.length}.json`), { ...entry, stdout: result.stdout, stderr: result.stderr });
    requireFact(!result.error && result.status === 0 && result.signal === null && finishedAt - startedAt <= limitMs, 'original measured subprocess failed, signalled or exceeded budget');
  }
  function phase(name, calls) {
    const begin = observed.length;
    try { for (const call of calls) execute(name, call.argv, call.report); }
    finally {
      const entries = observed.slice(begin); if (entries.length) phases[name] = { startedAt: entries[0].startedAt, finishedAt: entries.at(-1).finishedAt };
    }
  }
  try {
    phase('build', [{ argv: commands.build }]); phase('setup', [{ argv: commands.setup }]); phase('run', commands.run);
  } catch (error) { failure = error; }
  // Actual teardown and leak are attempted on failure too, never synthesized.
  for (const name of ['teardown', 'leak']) try { phase(name, [{ argv: commands[name] }]); } catch (error) { failure ??= error; }
  const startedAt = observed[0].startedAt, finishedAt = observed.at(-1).finishedAt;
  const measurements = { totalMs: finishedAt - startedAt, criticalPathMs: finishedAt - startedAt, longestShardMs: Math.max(0, ...observed.filter(c => c.phase === 'run').map(c => c.finishedAt - c.startedAt)) };
  for (const [name, interval] of Object.entries(phases)) measurements[`${name}Ms`] = interval.finishedAt - interval.startedAt;
  write(join(evidenceRoot, 'observations.json'), { invocation, sourceSha256, startedAt, finishedAt, phases, commands: observed, measurements });
  if (failure) throw failure;
  const reports = commands.run.map(run => ({ file: run.report, sha256: hash(bytes(resolve(evidenceRoot, run.report))) }));
  // Original reports are retained intact. No assertion result or PASS row is created.
  const actual = reports.flatMap(report => {
    const original = json(resolve(evidenceRoot, report.file));
    requireFact(original.success === true && original.numFailedTests === 0 && original.numPendingTests === 0 && original.numTodoTests === 0, 'original selected report did not pass completely');
    return original.testResults.flatMap(file => file.assertionResults.map(result => {
      requireFact(result.status === 'passed', 'original selected case did not pass');
      return JSON.stringify([relative(sourceRoot, resolve(sourceRoot, file.name)).split(sep).join('/'), reportedCaseName(result)]);
    }));
  });
  requireFact(actual.length === selected.length && new Set(actual).size === actual.length && selected.every(c => actual.includes(c)), 'original selected reports omit, add or duplicate cases');
  const descriptor = file => ({ file, sha256: hash(bytes(join(evidenceRoot, file))) });
  const planPath = write(join(evidenceRoot, 'validation-plan.json'), { version: 1, authorized: true, evidenceRoot, sourceRoot, current: { invocation, sourceSha256, startedAt, finishedAt }, inventory: descriptor('inventory.json'), observations: descriptor('observations.json'), reports });
  return { planPath };
}
