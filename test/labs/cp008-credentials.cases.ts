import { expect, it } from 'vitest';
import { executeMethods, forbiddenCln, loadBaker, nodes, readMethods, refusalFixtures, rejection, rig } from '../helpers/cp008-credentials.js';

// Literals: CP-008 B1 and SECURITY 3.1; pinned lnd-cmd-macaroon.go 54-108.
it('CP-008/B1 both LND nodes receive exact roles on independent nonzero root keys', async () => {
  const baker = await loadBaker();
  const fixture = await rig();
  const result = await baker.bakeLabCredentials(fixture.options);
  fixture.assertAccepted(result);
  expect(fixture.lndBakes()).toEqual([
    { node: 'lnd-p', root: '11', permissions: ['info:read', 'invoices:read', 'offchain:read'] },
    { node: 'lnd-p', root: '12', permissions: ['info:read', 'invoices:read', 'invoices:write', 'offchain:read', 'offchain:write'] },
    { node: 'lnd-r', root: '21', permissions: ['info:read', 'invoices:read', 'offchain:read'] },
    { node: 'lnd-r', root: '22', permissions: ['info:read', 'invoices:read', 'invoices:write', 'offchain:read', 'offchain:write'] },
  ]);
  for (const node of ['lnd-p', 'lnd-r'] as const) for (const role of ['read', 'execute']) {
    for (const operation of ['ListChannels', 'SendToRouteV2', 'ChangePassword', 'StopDaemon']) {
      const control = fixture.requests.find(request => request.node === node && request.credentialPath.endsWith(`${role}.macaroon`) && request.operation === operation);
      expect(control !== undefined, 'every LND role selects its positive and negative methods').toBe(true);
      expect(JSON.stringify(control?.params) === JSON.stringify(fixture.options.authorizationFixtures[node][operation]), 'request uses independently supplied named fixture parameters').toBe(true);
    }
  }
});

// SECURITY 3.2 and pinned createrune.json restriction_format: each array is OR, arrays are AND.
// The maximum and strict bound are independently literal, avoiding Number precision and off-by-one.
it('CP-008/B2 all CLN roles retain exact method alternatives separate rate and bigint amount restrictions', async () => {
  const baker = await loadBaker(), fixture = await rig();
  fixture.options.policy.maxPrincipalMsat = '9223372036854775807';
  fixture.options.policy.callsPerMinute = '18446744073709551616';
  fixture.options.policy.lndRootKeyIds['lnd-p'] = { read: '18446744073709551615', execute: '9007199254740993' };
  const result = await baker.bakeLabCredentials(fixture.options);
  fixture.assertAccepted(result);
  expect(fixture.lndBakes().filter(row => row.node === 'lnd-p').map(row => row.root).sort()).toEqual(['18446744073709551615', '9007199254740993']);
  const normal = (rows: string[][]) => rows.map(row => [...row].sort()).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const observed = fixture.runeBakes();
  expect(observed).toHaveLength(6);
  for (const node of ['cln-p', 'cln-r', 'cln-m']) {
    for (const role of ['read', 'execute']) {
      const minted = observed.find(row => row.node === node && row.role === role);
      expect(minted !== undefined, 'every required CLN role is minted').toBe(true);
      const expected = role === 'read' ? [readMethods, ['rate=18446744073709551616']] :
        [executeMethods, ['method/sendpay', 'pnameamount_msat<9223372036854775808'], ['rate=18446744073709551616']];
      expect(normal(minted?.restrictions ?? [])).toEqual(normal(expected));
    }
  }
});

it('CP-008/B2 acceptance selects actual positive negative and four amount controls for every CLN node', async () => {
  const baker = await loadBaker(), fixture = await rig();
  fixture.assertAccepted(await baker.bakeLabCredentials(fixture.options));
  for (const node of ['cln-p', 'cln-r', 'cln-m']) {
    const calls = fixture.requests.filter(request => request.node === node);
    for (const role of ['read', 'execute']) {
      const actual = calls.filter(request => request.credentialPath.endsWith(`${role}.rune`) && request.operation !== 'checkrune');
      expect(actual.some(request => request.operation === 'getinfo' && JSON.stringify(request.params) === '{}'), 'actual non-payment positive control').toBe(true);
      for (const method of forbiddenCln) expect(actual.some(request => request.operation === method), 'every absent/admin actual method is tested').toBe(true);
      expect(actual.some(request => request.operation === 'sendpay'), 'actual sendpay decision is checked for both roles').toBe(true);
      const expectedMethods = role === 'read' ? readMethods : executeMethods;
      for (const term of expectedMethods.filter(term => term.startsWith('method='))) {
        expect(actual.some(request => request.operation === term.slice(7)), 'declared method receives actual role control').toBe(true);
      }
    }
    const checks = calls.filter(request => request.operation === 'checkrune' && request.params['method'] === 'sendpay');
    const observed = checks.map(request => {
      const params = request.params['params'];
      if (typeof params !== 'object' || params === null) return 'malformed';
      const value = (params as Record<string, unknown>)['amount_msat'];
      return value === undefined ? 'missing' : String(value).replace(/msat$/, '');
    });
    for (const boundary of ['999', '1000', '1001', 'missing']) expect(observed).toContain(boundary);
    expect(calls.some(request => request.operation === 'checkrune' && request.params['method'] === 'getinfo'), 'amount restriction cannot block ordinary reads').toBe(true);
  }
  for (const request of fixture.requests) {
    expect(request.transport).toBe(request.node.startsWith('lnd-') ? 'lnd-rest' : 'clnrest');
    expect(Array.isArray(request.params), 'normal requests use named parameters').toBe(false);
  }
});

it('CP-008/B2 any allowed forbidden or denied legitimate control rejects provisional roles as a reference conflict', async () => {
  const baker = await loadBaker();
  for (const response of ['allow-denied', 'deny-allowed'] as const) {
    const fixture = await rig({ response });
    const error = await rejection(() => baker.bakeLabCredentials(fixture.options));
    fixture.assertClean(error);
    expect(fixture.requests.length, 'contradiction is observed through a real request port').toBeGreaterThan(0);
    expect(error instanceof Error && error.message.includes('REFERENCE_CONFLICT'), 'permission contradiction is identified without secret bodies').toBe(true);
  }
  const proof = await rig({ response: 'allow-denied' });
  Object.assign(proof.options.authorizationFixtures, { accepted: true, expectedResponses: { statusCode: 200 }, skipControls: true });
  proof.assertClean(await rejection(() => baker.bakeLabCredentials(proof.options)));
});

// Bounds/canonicality: contract policy interface; root IDs are nonzero uint64, distinct within node.
it('CP-008/B1 invalid absent noncanonical or reused root policy refuses before the first bake', async () => {
  const baker = await loadBaker();
  const next = await refusalFixtures();
  const mutations: ((policy: Record<string, unknown>) => void)[] = [
    policy => { delete policy['maxPrincipalMsat']; }, policy => { policy['maxPrincipalMsat'] = '0'; },
    policy => { policy['maxPrincipalMsat'] = '01'; }, policy => { policy['maxPrincipalMsat'] = '9223372036854775808'; },
    policy => { policy['maxPrincipalMsat'] = 1000; }, policy => { policy['maxPrincipalMsat'] = '-1'; },
    policy => { delete policy['callsPerMinute']; }, policy => { policy['callsPerMinute'] = '0'; },
    policy => { policy['callsPerMinute'] = '1.5'; }, policy => { policy['callsPerMinute'] = ' 60'; },
    policy => { policy['callsPerMinute'] = '1e3'; }, policy => { delete policy['lndRootKeyIds']; },
    policy => { policy['lndRootKeyIds'] = { 'lnd-p': { read: '11', execute: '11' }, 'lnd-r': { read: '21', execute: '22' } }; },
    policy => { policy['lndRootKeyIds'] = { 'lnd-p': { read: '0', execute: '12' }, 'lnd-r': { read: '21', execute: '22' } }; },
    policy => { policy['lndRootKeyIds'] = { 'lnd-p': { read: '01', execute: '12' }, 'lnd-r': { read: '21', execute: '22' } }; },
    policy => { policy['lndRootKeyIds'] = { 'lnd-p': { read: '18446744073709551616', execute: '12' }, 'lnd-r': { read: '21', execute: '22' } }; },
    policy => { policy['lndRootKeyIds'] = { 'lnd-p': { read: '11', execute: '12' } }; },
  ];
  for (const mutate of mutations) {
    const fixture = await next();
    mutate(fixture.options.policy as unknown as Record<string, unknown>);
    fixture.assertClean(await rejection(() => baker.bakeLabCredentials(fixture.options)));
    expect(fixture.commands, 'invalid policy never reaches credential creation').toHaveLength(0);
    expect(fixture.files.size).toBe(0);
    fixture.assertUntouched();
  }
  const missing = await next();
  delete (missing.options as unknown as Record<string, unknown>)['policy'];
  missing.assertClean(await rejection(() => baker.bakeLabCredentials(missing.options)));
  expect(missing.commands, 'omitted policy never receives an invented default').toHaveLength(0);
  missing.assertUntouched();
});

it('CP-008/B3 canonical role metadata uses checked exact bytes including padded runes with no secrets', async () => {
  const baker = await loadBaker(), fixture = await rig();
  fixture.assertAccepted(await baker.bakeLabCredentials(fixture.options));
  expect(fixture.runeBakes().every(row => row.bytes.toString('utf8').endsWith('==')), 'padding edge is actually exercised').toBe(true);
  expect(fixture.directories.length, 'secure directory port is used').toBeGreaterThan(0);
});

it('CP-008/B3 unsafe parent descriptor ownership broad access or reparse refusal destroys partial outputs', async () => {
  // One set of secure roots serves every refusal; each case still gets fresh boundary state (rig reuse).
  const baker = await loadBaker(), owner = structuredClone((await rig()).selected);
  for (const permissions of ['broad-directory', 'broad-file', 'symlink', 'foreign-owner'] as const) {
    const fixture = await rig({ permissions }, owner);
    fixture.assertClean(await rejection(() => baker.bakeLabCredentials(fixture.options)));
    expect(fixture.rejectedPermission(), 'ordinary secure permission boundary actually rejects').toBe(true);
  }
  for (const path of ['relative-root', '../escape']) {
    const fixture = await rig({}, owner); fixture.options.owner.runtimeRoot = path;
    fixture.assertClean(await rejection(() => baker.bakeLabCredentials(fixture.options)));
    expect(fixture.commands, 'unsafe owner path refuses before baking').toHaveLength(0);
  }
  const changed = await rig({ permissions: 'readback' }, owner);
  changed.assertClean(await rejection(() => baker.bakeLabCredentials(changed.options)));
  expect(changed.checked.size, 'changed bytes actually arrive through descriptor readback').toBeGreaterThan(0);
});

it.each(['exit', 'malformed', 'oversize', 'throw'] as const)('CP-008/B3 process %s secret output cannot become accepted credentials', async process => {
  const baker = await loadBaker();
  const fixture = await rig({ process });
  fixture.assertClean(await rejection(() => baker.bakeLabCredentials(fixture.options)));
  expect(fixture.commands.length, 'failure follows actual baking attempt').toBeGreaterThan(0);
}, 15_000);

it('CP-008/B3 malformed response transport error or exhausted rate cannot masquerade as permission denial', async () => {
  const baker = await loadBaker();
  for (const response of ['malformed', 'transport', 'rate'] as const) {
    const controller = new AbortController(), fixture = await rig({ response });
    fixture.options.signal = controller.signal;
    const timer = setTimeout(() => { controller.abort(); }, 250);
    try {
      fixture.assertClean(await rejection(() => baker.bakeLabCredentials(fixture.options)));
      expect(fixture.requests.length, 'response is observed through normal transport').toBeGreaterThan(0);
    } finally { clearTimeout(timer); }
  }
});

// SECURITY 3.1; pinned rpcserver.go v1 LookupInvoice -> invoices:read,
// invoices_server.go /invoicesrpc.Invoices/LookupInvoiceV2 -> invoices:write.
it('CP-008/B4 invoice positive controls retain v1 read authority and redact unsettled preimages', async () => {
  const baker = await loadBaker(), fixture = await rig();
  fixture.assertAccepted(await baker.bakeLabCredentials(fixture.options));
  for (const node of ['lnd-p', 'lnd-r']) {
    const calls = fixture.requests.filter(request => request.node === node);
    expect(calls.some(request => request.operation === 'LookupInvoice' && request.credentialPath.endsWith('read.macaroon')), 'v1 invoice read is positively controlled').toBe(true);
    expect(calls.some(request => request.operation === 'LookupInvoiceV2' && request.credentialPath.endsWith('read.macaroon')), 'V2 read denial is independently controlled').toBe(true);
    expect(calls.some(request => request.operation === 'LookupInvoiceV2' && request.credentialPath.endsWith('execute.macaroon')), 'V2 write positive control disambiguates denial').toBe(true);
  }
  expect(fixture.lndBakes().filter(row => row.root === '11' || row.root === '21').every(row => !row.permissions.includes('invoices:write'))).toBe(true);
});

it('CP-008/Bowner concurrent disjoint owners retain exact role files and cancellation removes only its owner', async () => {
  const baker = await loadBaker(), first = await rig(), second = await rig();
  second.options.owner.ports = { lndRest: 28110, clnRest: 28111, toxiproxy: 28112 };
  expect(first.selected.project === second.selected.project).toBe(false);
  expect(new Set([first.selected.runtimeRoot, first.selected.tmpRoot, first.selected.sentinelRoot, first.selected.evidenceRoot,
    second.selected.runtimeRoot, second.selected.tmpRoot, second.selected.sentinelRoot, second.selected.evidenceRoot]).size).toBe(8);
  let arrivals = 0, release: () => void = () => undefined;
  const barrier = new Promise<void>(resolve => { release = resolve; });
  for (const fixture of [first, second]) {
    const write = fixture.options.ports.permissions.writeExclusive.bind(fixture.options.ports.permissions);
    let reached = false;
    fixture.options.ports.permissions.writeExclusive = async (path, bytes) => {
      if (!reached) { reached = true; arrivals += 1; if (arrivals === 2) release(); await barrier; }
      await write(path, bytes);
    };
  }
  const accepted = await Promise.all([baker.bakeLabCredentials(first.options), baker.bakeLabCredentials(second.options)]);
  first.assertAccepted(accepted[0]); second.assertAccepted(accepted[1]);
  expect(first.files.size).toBeGreaterThanOrEqual(10); expect(second.files.size).toBeGreaterThanOrEqual(10);
  const controller = new AbortController(), cancelled = await rig({ abortAfterWrite: controller });
  cancelled.options.signal = controller.signal;
  cancelled.assertClean(await rejection(() => baker.bakeLabCredentials(cancelled.options)));
  expect(controller.signal.aborted, 'cancellation actually follows provisional output').toBe(true);
  for (const node of nodes) {
    expect(first.files.has(accepted[0].credentials[node].read.path), 'successful independent owner remains intact').toBe(true);
    expect(second.files.has(accepted[1].credentials[node].execute.path)).toBe(true);
  }
});
