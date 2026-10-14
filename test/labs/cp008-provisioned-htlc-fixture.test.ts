// D75 requires newly generated CLN read/execute roles to authorize one bounded
// listhtlcs read. The public fixture provisioner must supply that native request
// before the independent credential baker validates all declared alternatives.
// Native schema: CLN v26.06.9 listhtlcs.json index=created/start/limit<=500.
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { addInvoiceResponse } from '../fakes/lnd/responses.js';
import { repoRoot } from '../helpers/cli.js';
import { syntheticInvoice } from '../helpers/cp004-invoice.js';
import { loadBaker, nodes, rig, type BakerOptions, type Node, type Params, type Request } from '../helpers/cp008-credentials.js';
import { testRoot } from '../helpers/env.js';

interface Provisioner {
  provisionAuthorizationFixtures(input: {
    owner: BakerOptions['owner']; policy: BakerOptions['policy'];
    identities: Record<Node, { pubkey: string; fundingAddress: string; credential: { path: string } }>;
    topology: { channels: { from: Node; to: Node }[] };
    permissions: BakerOptions['ports']['permissions'];
    permissionRequest(request: Request): Promise<{ statusCode: number; body: Record<string, unknown> }>;
    runProcess: BakerOptions['ports']['runProcess'];
  }): Promise<{ fixtures: BakerOptions['authorizationFixtures']; cleanup(): Promise<void> }>;
}

it('CP-008/B2 provisioned native fixtures supply bounded incoming HTLC history for every CLN role without weakening existing permission controls', async () => {
  const fixture = await rig();
  const secret = randomBytes(32);
  writeFileSync(join(testRoot('FLUXWARDEN_SENTINEL_DIR'), `provisioned-payment-secret-${randomBytes(8).toString('hex')}.bin`), secret, { mode: 0o600 });
  const identities = Object.fromEntries(nodes.map((node, index) => [node, {
    pubkey: `02${String(index + 1).padStart(2, '0').repeat(32)}`, fundingAddress: `owned-synthetic-${node}`,
    credential: { path: join(fixture.options.owner.runtimeRoot, `${node}-bootstrap`) },
  }])) as Record<Node, { pubkey: string; fundingAddress: string; credential: { path: string } }>;
  const provisioner = await import(pathToFileURL(join(repoRoot, 'labs/docker/credential-fixtures.mjs')).href) as Provisioner;
  const provisioned = await provisioner.provisionAuthorizationFixtures({
    owner: fixture.options.owner, policy: fixture.options.policy, identities,
    topology: { channels: [{ from: 'cln-p', to: 'cln-r' }, { from: 'cln-r', to: 'cln-m' }, { from: 'lnd-p', to: 'lnd-r' }] },
    permissions: fixture.options.ports.permissions,
    runProcess: () => Promise.resolve({ exitCode: 0, stdout: JSON.stringify({ rune: randomBytes(31).toString('base64'), unique_id: '31' }), stderr: '' }),
    permissionRequest: request => {
      if (request.operation === 'invoice') {
        const hash = createHash('sha256').update(Buffer.from(String(request.params['preimage']), 'hex')).digest('hex');
        return Promise.resolve({ statusCode: 201, body: { payment_hash: hash, payment_secret: secret.toString('hex'), bolt11: syntheticInvoice(hash) } });
      }
      if (request.operation === 'AddInvoice') {
        const hash = createHash('sha256').update(Buffer.from(String(request.params['r_preimage']), 'base64')).digest('hex');
        return Promise.resolve({ statusCode: 200, body: addInvoiceResponse(hash, secret.toString('hex'), syntheticInvoice(hash)) });
      }
      if (request.operation === 'QueryRoutes') return Promise.resolve({ statusCode: 200, body: { routes: [{
        total_time_lock: 144, total_fees_msat: '0', total_amt_msat: '1000',
        hops: [{ chan_id: '1', pub_key: request.params['pub_key'], amt_to_forward_msat: '1000', fee_msat: '0', expiry: 144 }],
      }] } });
      if (['sendpay', 'blacklistrune', 'delinvoice', 'CancelInvoice'].includes(request.operation)) return Promise.resolve({ statusCode: 201, body: {} });
      return Promise.reject(new Error(`Unexpected ordinary provisioning operation ${request.operation}`));
    },
  });
  try {
  for (const node of ['cln-p', 'cln-r', 'cln-m'] as const) {
    const htlcs: Params | undefined = provisioned.fixtures[node]['listhtlcs'];
    expect(htlcs, `${node} must supply its real native positive authorization fixture`).toBeDefined();
    expect(htlcs?.['index']).toBe('created');
    expect(Number(htlcs?.['limit'])).toBeGreaterThan(0);
    expect(Number(htlcs?.['limit'])).toBeLessThanOrEqual(500);
  }
  fixture.options.authorizationFixtures = provisioned.fixtures;
  const result = await (await loadBaker()).bakeLabCredentials(fixture.options);
  fixture.assertAccepted(result);
  for (const node of ['cln-p', 'cln-r', 'cln-m'] as const) for (const role of ['read', 'execute'] as const) {
    const history = fixture.requests.filter(request => request.node === node && request.operation === 'listhtlcs' && request.credentialPath.endsWith(`${role}.rune`));
    expect(history.length).toBeGreaterThanOrEqual(1);
    expect(history.every(request => request.params['index'] === 'created' && Number(request.params['limit']) <= 500)).toBe(true);
  }
  } finally { await provisioned.cleanup(); }
});
