// SECURITY INV-11: one registered value may span writes and line
// breaks. Recognition must survive those boundaries and preserve later text.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { expect, it } from 'vitest';
import { capturedSink, outputModule, secretType, sentinelRoot } from '../helpers/output.js';

for (const stream of ['stdout', 'stderr'] as const) {
  it(`CP-003/REG-CORE004 split registered values remain private until finalized on ${stream}`, async () => {
    const bytes = createHash('sha256').update('disposable split value fixture').digest();
    writeFileSync(join(sentinelRoot(), `external-prefix-${stream}.bin`), bytes, { mode: 0o600 });
    const Secret = await secretType();
    const { createOutput } = await outputModule();
    const target = capturedSink();
    const output = createOutput({ stdout: target.sink, stderr: target.sink, secrets: [new Secret(bytes)] });
    const encoded = bytes.toString('hex');
    const incompleteValue = encoded.slice(0, -1);
    await output.write(incompleteValue, { stream });
    expect(target.text().includes(incompleteValue), 'undecidable registered-value suffix is retained').toBe(false);
    await output.write(encoded.slice(-1), { stream });
    await output.write(' / following ordinary message.\n', { stream });
    // SECURITY INV-11 applies to the complete value across writes.
    expect(target.text().includes(incompleteValue), 'registered value prefix remains private').toBe(false);
    expect(target.text().replace(/\s/g, '').includes(encoded), 'complete registered value remains private').toBe(false);
    await output.finalize();
    expect(target.text().endsWith(' / following ordinary message.\n')).toBe(true);
  });

  it(`CP-003/REG-CORE004 registered-value recognition spans writes and newlines on ${stream}`, async () => {
    const bytes = createHash('sha256').update('disposable stream fixture').digest();
    writeFileSync(join(sentinelRoot(), `external-stream-${stream}.bin`), bytes, { mode: 0o600 });
    const Secret = await secretType();
    const { createOutput } = await outputModule();
    const target = capturedSink();
    const other = capturedSink();
    const output = createOutput({ stdout: stream === 'stdout' ? target.sink : other.sink,
      stderr: stream === 'stderr' ? target.sink : other.sink, secrets: [new Secret(bytes)] });
    const encoded = bytes.toString('hex');
    await output.write('before / ', { stream });
    await output.write(encoded.slice(0, 21) + '\n', { stream });
    await output.write(encoded.slice(21, 43) + '\n', { stream });
    await output.write(encoded.slice(43), { stream });
    await output.write(' / ordinary café diagnostic.\n', { stream });
    await output.finalize();
    // Boolean assertions keep disposable secret material out of failure logs.
    expect(target.text().replace(/\s/g, '').includes(encoded), 'wrapped registered value remains absent').toBe(false);
    expect(target.text().startsWith('before / '), 'ordinary prefix is retained').toBe(true);
    expect(target.text().endsWith(' / ordinary café diagnostic.\n'), 'following output is preserved exactly').toBe(true);
    expect(other.text()).toBe('');
  });
}

it('CP-003/REG-CORE004 ordinary successive multiline writes preserve every byte on both streams', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const stdout = capturedSink();
  const stderr = capturedSink();
  const output = createOutput({ stdout: stdout.sink, stderr: stderr.sink,
    secrets: [new Secret(createHash('sha256').update('ordinary output preservation control').digest())] });
  for (const text of ['a normal ', 'message\n', 'with café\n', 'and a final line.']) await output.write(text, { stream: 'stdout' });
  await output.write('diagnostic\n', { stream: 'stderr' });
  await output.write('continued.', { stream: 'stderr' });
  await output.finalize();
  expect(stdout.text()).toBe('a normal message\nwith café\nand a final line.');
  expect(stderr.text()).toBe('diagnostic\ncontinued.');
});

it('CP-003/REG-CORE004 finalization drains an unmatched ordinary fragment under transport backpressure', async () => {
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const bytes = createHash('sha256').update('disposable finalization backpressure fixture').digest();
  const fragment = bytes.toString('hex').slice(0, -1);
  let hold = false;
  let release: (() => void) | undefined;
  let entered: (() => void) | undefined;
  const waitingForWrite = new Promise<void>(resolve => { entered = resolve; });
  const chunks: Buffer[] = [];
  const sink = new Writable({ highWaterMark: 1, write(chunk: Buffer, _encoding, callback) {
    chunks.push(Buffer.from(chunk));
    if (!hold) { callback(); return; }
    release = callback;
    entered?.();
  } });
  const output = createOutput({ stdout: sink, stderr: capturedSink().sink, secrets: [new Secret(bytes)] });
  await output.write(fragment, { stream: 'stdout', exitCode: 7 });
  expect(chunks.length, 'no undecidable fragment is emitted before finalization').toBe(0);
  hold = true;
  let finished = false;
  const draining = output.finalize().then(() => { finished = true; });
  await waitingForWrite;
  expect(finished).toBe(false);
  if (release === undefined) throw new Error('the transport must receive the ordinary fragment');
  release();
  await draining;
  expect(Buffer.concat(chunks).toString('utf8') === fragment, 'unmatched ordinary fragment is released exactly').toBe(true);
  expect(sink.writableEnded).toBe(false);
});
