// AUDIT-03 / SPEC output / SECURITY output redaction: a successful node reply
// cannot return a credential which the same command has just loaded.
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { getinfo } from '../fakes/cln/responses.js';
import { getInfo, LND_PUBKEY } from '../fakes/lnd/responses.js';
import { demo, jsonDocument, rec } from '../helpers/cpw-cli.js';
import { createDatabase, lndNode, nodeCert, runCli, scratch, writeConfig } from '../helpers/cp016-cli.js';
import { registerMoneySafetyCredentials } from '../helpers/public-money-safety.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

for (const json of [true, false]) {
  it(`CP-003/AUDIT-03 successful nodes inspect redacts its loaded rune in ${json ? 'JSON' : 'text'}`, async () => {
    const d = await demo(open, { withKey: false });
    registerMoneySafetyCredentials([d.cln.runeFile]);
    const original = d.cln.fake.result;
    // getinfo alias is node-controlled text (CLN v26.06.9 getinfo.json).
    d.cln.fake.result = (context, behavior, value) => {
      original(context, behavior, context.request.url === '/v1/getinfo' ? { ...getinfo(), alias: d.cln.rune } : value);
    };
    const run = await d.run([...(json ? ['--json'] : []), 'nodes', 'inspect', 'cln-m', '--capabilities']);
    expect(run.status).toBe(0);
    const marker = `[redacted fp:${createHash('sha256').update(d.cln.rune).digest('hex').slice(0, 16)}]`;
    // Boolean assertions keep raw sentinel bytes out of assertion diagnostics.
    expect(`${run.stdout}${run.stderr}`.includes(d.cln.rune), 'loaded credential never reaches either stream').toBe(false);
    expect(run.stdout.includes(marker), 'successful metadata carries the credential fingerprint marker').toBe(true);
    if (json) {
      const document = jsonDocument(run);
      expect(document['ok']).toBe(true);
      expect(rec(document['result'])['alias'] === marker, 'JSON alias is the marker').toBe(true);
    } else {
      expect(run.stdout).toContain('cln-m');
    }
  });
}

for (const json of [true, false]) {
  it(`CP-003/AUDIT-03 successful LND metadata redacts its loaded macaroon echo in ${json ? 'JSON' : 'text'}`, async () => {
    const dir = scratch('audit-metadata-lnd');
    const info = getInfo();
    const lnd = await lndNode(dir, open, { info });
    registerMoneySafetyCredentials([lnd.macaroon]);
    // Native GetInfo alias is node-controlled. Echo the HTTP authentication
    // representation (hex), rather than the underlying binary credential.
    info['alias'] = lnd.macaroonHex;
    const database = join(dir, 'state', 'fluxwarden.db');
    await createDatabase(database);
    const config = writeConfig(dir, { database, nodes: [{ name: 'lnd-r', implementation: 'lnd',
      url: lnd.url, credential: lnd.macaroon, tlsCert: nodeCert(), expectedPubkey: LND_PUBKEY }] });
    const run = await runCli([...(json ? ['--json'] : []), 'nodes', 'inspect', 'lnd-r', '--capabilities', '--config', config]);
    expect(run.status).toBe(0);
    const marker = `[redacted fp:${createHash('sha256').update(Buffer.from(lnd.macaroonHex, 'hex')).digest('hex').slice(0, 16)}]`;
    expect(`${run.stdout}${run.stderr}`.includes(lnd.macaroonHex), 'successful metadata contains no authentication value').toBe(false);
    expect(run.stdout.includes(marker), 'loaded binary credential uses its fingerprint marker').toBe(true);
    if (json) expect(rec(jsonDocument(run)['result'])['alias'] === marker, 'JSON alias is the marker').toBe(true);
    else expect(run.stdout).toContain('lnd-r');
  });
}
