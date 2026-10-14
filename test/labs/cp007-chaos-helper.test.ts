import { expect, it } from 'vitest';
import { LabInvalidError, withChaos } from '../helpers/chaos.js';
import { barrier, stateClient, toxics, required } from '../helpers/cp007-toxiproxy.js';

// CP-007 B3 / ARCHITECTURE 10.2 / D41: restoration after every outcome, own proxies only.
it('CP-007/B3 partial setup success throw INVALID deadline and abort restore own state and preserve foreign faults', async () => {
  for (const outcome of ['success', 'setup', 'throw', 'INVALID', 'deadline', 'abort']) {
    const fake = stateClient(), before = structuredClone(fake.state['foreign']), abort = new AbortController();
    const operation = withChaos({ client: fake.client, proxies: ['lnd-r-rest', 'cln-m-rest'], timeoutMs: 20, signal: abort.signal, setup: async control => {
      await control.add('lnd-r-rest', required(toxics[0])); await control.enable('cln-m-rest', false);
      if (outcome === 'setup') throw new Error('partial setup failed');
    } }, () => {
      if (outcome === 'throw') throw new Error('body failed');
      if (outcome === 'INVALID') throw new LabInvalidError('body INVALID');
      if (outcome === 'abort') { abort.abort(); return new Promise<never>(() => {}); }
      if (outcome === 'deadline') return new Promise<never>(() => {});
      return 'done';
    });
    if (outcome === 'success') expect(await operation).toBe('done');
    else if (outcome === 'INVALID') await expect(operation).rejects.toBeInstanceOf(LabInvalidError);
    else await expect(operation, `${outcome} cannot pass`).rejects.toThrow(({ setup: 'partial setup failed', throw: 'body failed', deadline: 'chaos operation deadline exceeded', abort: 'chaos operation aborted' } as Record<string, string>)[outcome]);
    for (const name of ['lnd-r-rest', 'cln-m-rest']) expect(fake.state[name]).toMatchObject({ enabled: true, toxics: [] });
    expect(fake.state['foreign']).toEqual(before); expect(fake.writes.includes('reset')).toBe(false);
    expect(fake.reads(), `${outcome} independent final read`).toBeGreaterThanOrEqual(3);
  }
});

it('CP-007/B3 failed restoration independently rereads and refuses the next dirty case', async () => {
  const fake = stateClient(); let bodies = 0;
  const enable = fake.client.enable.bind(fake.client);
  fake.client.enable = (name, enabled = true) => enabled ? Promise.reject(new Error('restoration refused')) : enable(name, enabled);
  await expect(withChaos({ client: fake.client, proxies: ['lnd-r-rest'], setup: control => control.enable('lnd-r-rest', false) }, () => { bodies++; })).rejects.toBeInstanceOf(LabInvalidError);
  expect(fake.reads()).toBe(3);
  await expect(withChaos({ client: fake.client, proxies: ['lnd-r-rest'], setup: () => {} }, () => { bodies++; })).rejects.toBeInstanceOf(LabInvalidError);
  expect(bodies, 'dirty next case cannot execute').toBe(1); expect(fake.reads()).toBe(6);
});

it('CP-007/Bowner helpers serialize shared client state while distinct owners overlap without resets', async () => {
  const shared = stateClient(), independent = stateClient(), entered = barrier(), released = barrier(), otherEntered = barrier();
  const order: string[] = [];
  const first = withChaos({ client: shared.client, proxies: ['lnd-r-rest'], setup: () => {} }, async () => { order.push('first'); entered.open(); await released.promise; });
  await entered.promise;
  const second = withChaos({ client: shared.client, proxies: ['cln-m-rest'], setup: () => { order.push('second'); } }, () => {});
  const other = withChaos({ client: independent.client, proxies: ['lnd-r-rest'], setup: control => control.enable('lnd-r-rest', false) }, () => { order.push('other'); otherEntered.open(); });
  await otherEntered.promise; expect(order).toEqual(['first', 'other']);
  released.open(); await Promise.all([first, second, other]); expect(order).toEqual(['first', 'other', 'second']);
  expect([...shared.writes, ...independent.writes].includes('reset')).toBe(false);
});

it('CP-007/B5 restart removes owned proxy observation and forces INVALID after an independent restoration read', async () => {
  const fake = stateClient();
  await expect(withChaos({ client: fake.client, proxies: ['lnd-r-rest'], setup: control => control.add('lnd-r-rest', required(toxics[0])) }, () => { delete fake.state['lnd-r-rest']; })).rejects.toBeInstanceOf(LabInvalidError);
  expect(fake.reads()).toBe(3);
});

it('CP-007/B3 stalled toxic removal has bounded independent verification and still reenables other owned proxies', async () => {
  const fake = stateClient();
  fake.client.remove = () => new Promise<never>(() => {});
  await expect(withChaos({ client: fake.client, proxies: ['lnd-r-rest', 'cln-m-rest'], timeoutMs: 20, setup: async control => {
    await control.add('lnd-r-rest', required(toxics[0])); await control.enable('cln-m-rest', false);
  } }, () => {})).rejects.toBeInstanceOf(LabInvalidError);
  expect(required(fake.state['cln-m-rest']).enabled).toBe(true); expect(fake.reads()).toBe(3);
  let nextBody = false;
  await expect(withChaos({ client: fake.client, proxies: ['lnd-r-rest'], timeoutMs: 20, setup: () => {} }, () => { nextBody = true; })).rejects.toBeInstanceOf(LabInvalidError);
  expect(nextBody).toBe(false); expect(fake.reads()).toBe(6);
});
