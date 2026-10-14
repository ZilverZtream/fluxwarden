import { performance } from 'node:perf_hooks';
import { expect, it } from 'vitest';
import { withChaos, LabInvalidError } from '../helpers/chaos.js';
import { getInfo, liveClient, liveOracle, liveOwners } from '../helpers/cp007-live.js';
import { barrier, required } from '../helpers/cp007-toxiproxy.js';
import { dockerText } from '../helpers/cp006-oracle.js';

// Primary latency.go: milliseconds; jitter zero makes a deterministic lower bound.
it('CP-007/R2 LND REST latency is observed with monotonic timing against a no-toxic response', async () => {
  const owner = required(liveOwners()[0]); liveOracle(owner); const control = await liveClient(owner);
  const baselineStart = performance.now(), baseline = await getInfo(owner), baselineMs = performance.now() - baselineStart;
  expect(baseline.status).toBe(200);
  await withChaos({ client: control, proxies: ['lnd-r-rest'], setup: client => client.add('lnd-r-rest', { name: 'reference-lag', type: 'latency', stream: 'downstream', toxicity: 1, attributes: { latency: 250, jitter: 0 } }) }, async client => {
    expect((await client.list())['lnd-r-rest']?.toxics).toContainEqual({ name: 'reference-lag', type: 'latency', stream: 'downstream', toxicity: 1, attributes: { latency: 250, jitter: 0 } });
    const start = performance.now(), delayed = await getInfo(owner), elapsed = performance.now() - start;
    expect(delayed.status).toBe(200); expect(delayed.body).toEqual(baseline.body);
    expect(elapsed).toBeGreaterThanOrEqual(250); expect(elapsed).toBeGreaterThan(baselineMs);
  });
  expect((await control.list())['lnd-r-rest']).toMatchObject({ enabled: true, toxics: [] });
});

// Primary timeout.go: timeout 0 holds bytes until removed. Read-only request proves sent transport phase.
it('CP-007/R3 timeout after request write produces sent transport loss and observed proxy restoration', async () => {
  const owner = required(liveOwners()[0]); liveOracle(owner); const control = await liveClient(owner);
  await withChaos({ client: control, proxies: ['lnd-r-rest'], setup: client => client.add('lnd-r-rest', { name: 'reference-hold', type: 'timeout', stream: 'downstream', toxicity: 1, attributes: { timeout: 0 } }) }, async () => {
    let failure: unknown; try { await getInfo(owner, 200); } catch (error) { failure = error; }
    expect(failure).toMatchObject({ phase: 'sent' });
    expect(Object.keys(failure as object).sort()).toEqual(['phase']);
  });
  expect((await control.list())['lnd-r-rest']).toMatchObject({ enabled: true, toxics: [] });
  expect((await getInfo(owner)).status).toBe(200);
});

it('CP-007/R4 independent owners overlap and restart partial errors timeout and abort restore or report INVALID', async () => {
  const owners = liveOwners(); if (owners.length !== 2 || !required(owners[0]).restart) throw new LabInvalidError('two explicit owners and owner-only daemon restart authorization required');
  const controls = await Promise.all(owners.map(liveClient));
  const entered = barrier(), release = barrier();
  const first = withChaos({ client: required(controls[0]), proxies: ['lnd-r-rest'], setup: client => client.enable('lnd-r-rest', false) }, async () => { entered.open(); await release.promise; });
  await entered.promise;
  await withChaos({ client: required(controls[1]), proxies: ['cln-m-rest'], setup: client => client.enable('cln-m-rest', false) }, async () => {
    expect((await required(controls[0]).list())['lnd-r-rest']?.enabled).toBe(false);
  });
  expect((await required(controls[0]).list())['lnd-r-rest']?.enabled).toBe(false); release.open(); await first;
  for (const outcome of ['partial', 'timeout', 'signal', 'restart']) {
    const signal = new AbortController();
    const operation = withChaos({ client: required(controls[0]), proxies: ['lnd-r-rest'], timeoutMs: 2000, signal: signal.signal, setup: async client => {
      await client.enable('lnd-r-rest', false); if (outcome === 'partial') throw new Error('partial setup failed');
    } }, () => {
      if (outcome === 'restart') { dockerText(['restart', dockerText(['ps', '-q', '--filter', `label=com.docker.compose.project=${required(owners[0]).project}`, '--filter', 'label=com.docker.compose.service=toxiproxy'])]); return; }
      if (outcome === 'signal') signal.abort();
      return new Promise<never>(() => {});
    });
    if (outcome === 'restart') {
      let invalid: unknown;
      try { await operation; } catch (error) { invalid = error; }
      if (invalid !== undefined) expect(invalid).toBeInstanceOf(LabInvalidError);
    } else await expect(operation, `${outcome} cannot pass`).rejects.toBeInstanceOf(Error);
    expect((await required(controls[0]).list())['lnd-r-rest']).toMatchObject({ enabled: true, toxics: [] });
    expect((await required(controls[1]).list())['cln-m-rest']).toMatchObject({ enabled: true, toxics: [] });
  }
});
