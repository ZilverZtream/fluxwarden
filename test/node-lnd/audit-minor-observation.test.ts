// Interface: existing LND execution adapter observation port; transport scripts cite pinned gateway behaviors in the fake.
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { certificatePath, type FakeServer } from '../fakes/https.js';
import { startFakeLnd } from '../fakes/lnd/fake-lnd.js';
import { attempt, b64, payment } from '../fakes/lnd/responses.js';
import { loadLndRest } from '../helpers/adapter-interfaces.js';
import { scratchDir } from '../helpers/cli.js';
import { loadLndExecute, sha256 } from '../helpers/cp030-execution.js';

const servers: FakeServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

for (const ending of ['terminal', 'ordinary-end', 'authentication-error', 'terminal-authentication-error'] as const) {
  it(`CP-032/B2 REG-LND003 REG-LND004 observation ${ending} retains only justified current evidence (INV-04)`, async () => {
    const macaroon = randomBytes(96);
    const macaroonPath = join(scratchDir('observe'), 'local.macaroon');
    writeFileSync(macaroonPath, macaroon);
    const preimage = randomBytes(32);
    const hash = sha256(preimage);
    const record = ending.startsWith('terminal')
      ? payment({ payment_hash: hash, status: 'SUCCEEDED', payment_preimage: preimage.toString('hex'), value_msat: '100000000', fee_msat: '150000',
        htlcs: [{ ...attempt('SUCCEEDED', '41'), preimage: b64(preimage.toString('hex')) }], failure_reason: 'FAILURE_REASON_NONE' })
      : payment({ payment_hash: hash, status: 'IN_FLIGHT', htlcs: [attempt('IN_FLIGHT', '41')] });
    const fake = await startFakeLnd({ macaroonHex: macaroon.toString('hex'), routes: { 'GET /v2/router/track/{payment_hash}': (context, lnd) => {
      const lines = [JSON.stringify({ result: record }) + '\n'];
      if (ending.includes('authentication-error')) lines.push(JSON.stringify({ error: { code: 16, message: 'ordinary authentication failure' } }) + '\n');
      lnd.stream(context, 'trackpayment-stream', lines, 'finish');
    } } });
    servers.push(fake);
    const { openLndRest } = await loadLndRest();
    const rest = await openLndRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), macaroonPath, timeoutMs: 5_000 });
    const { LndExecutionAdapter } = await loadLndExecute();
    const adapter = new LndExecutionAdapter(rest, { trackDeadlineMs: 2_000 });
    const observed = await adapter.observePayment(hash);
    if (ending.startsWith('terminal')) expect(observed).toMatchObject({ kind: 'SUCCEEDED', feeMsat: 150_000n, htlcCount: 1, preimageMatchesHash: true });
    else if (ending === 'ordinary-end') expect(observed).toEqual({ kind: 'IN_FLIGHT' });
    else {
      expect(observed.kind).toBe('AMBIGUOUS');
      if (observed.kind === 'AMBIGUOUS') expect(observed.cause.length).toBeGreaterThan(0);
    }
    expect(fake.requests.filter(request => request.url.startsWith('/v2/router/track/'))).toHaveLength(1);
    expect(fake.requests.every(request => request.method === 'GET')).toBe(true);
  });
}
