// Interface: the existing TLS fakes and public adapter ports. Scripted node facts cite
// lnd v0.21.4-beta lightning.proto/router.proto and CLN v26.06.9 doc/schemas/{sendpay,waitsendpay,listsendpays}.json.
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { certificatePath } from '../fakes/https.js';
import { startFakeLnd, type LndRoute } from '../fakes/lnd/fake-lnd.js';
import { startFakeCln, type ClnHandler } from '../fakes/cln/fake-cln.js';
import { loadClnApi, loadClnRest, loadLndApi, loadLndRest } from './adapter-interfaces.js';
import { loadClnExecute, loadLndExecute, sha256 } from './cp030-execution.js';
import { scratchDir } from './cli.js';

export const WIRE_PREIMAGE = randomBytes(32), WIRE_HASH = sha256(WIRE_PREIMAGE);
export async function lndWire(routes: Partial<Record<string, LndRoute>>) {
  const directory = scratchDir('chaos-wire-lnd'), macaroon = randomBytes(96), macaroonPath = join(directory, 'macaroon.bin');
  writeFileSync(macaroonPath, macaroon, { mode: 0o600 });
  const fake = await startFakeLnd({ macaroonHex: macaroon.toString('hex'), routes });
  try {
    const { openLndRest } = await loadLndRest(), { LndReadApi } = await loadLndApi(), { LndExecutionAdapter } = await loadLndExecute();
    const rest = await openLndRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), macaroonPath, timeoutMs: 2000 });
    return { fake, rest, api: new LndReadApi(rest), execution: new LndExecutionAdapter(rest, { trackDeadlineMs: 1000 }), close: () => fake.close() };
  } catch (error) { await fake.close(); throw error; }
}

export async function clnWire(methods: Partial<Record<string, ClnHandler>>) {
  const directory = scratchDir('chaos-wire-cln'), rune = `test-only-${randomBytes(12).toString('hex')}`, runePath = join(directory, 'rune.txt');
  writeFileSync(runePath, rune, { mode: 0o600 });
  const fake = await startFakeCln({ rune, methods });
  try {
    const { openClnRest } = await loadClnRest(), { ClnReadApi } = await loadClnApi(), { ClnExecutionAdapter } = await loadClnExecute();
    const rest = await openClnRest({ host: fake.host, port: fake.port, tlsCertPath: certificatePath('node'), runePath, timeoutMs: 2000 });
    return { fake, rest, api: new ClnReadApi(rest), execution: new ClnExecutionAdapter(rest, { ownId: `03${'cd'.repeat(32)}`, waitChunkSeconds: 1, attemptDeadlineMs: 1500 }), close: () => fake.close() };
  } catch (error) { await fake.close(); throw error; }
}

export function trackRecord(record: Record<string, unknown>): LndRoute {
  return (context, fake) => { fake.stream(context, 'matrix-track', [`${JSON.stringify({ result: record })}\n`], 'finish'); };
}
