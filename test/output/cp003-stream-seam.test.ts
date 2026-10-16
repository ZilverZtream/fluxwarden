import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { capturedSink, outputModule, secretType, sentinelRoot } from '../helpers/output.js';

it('CP-003/B10 successive completed writes cannot assemble a registered credential on one transport', async () => {
  // Output redaction must hold across successive writes on one transport.
  // Assert joined transport bytes and preserve independent ordinary fragments
  // when finite output is finalized.
  const bytes = createHash('sha256').update('disposable successive-write credential fixture').digest();
  writeFileSync(join(sentinelRoot(), 'successive-write.bin'), bytes, { mode: 0o600 });
  const Secret = await secretType();
  const { createOutput } = await outputModule();
  const hex = bytes.toString('hex');
  const base64 = bytes.toString('base64');
  const representations: [string, string][] = [
    ['hex-lower', hex],
    ['hex-upper', hex.toUpperCase()],
    ['hex-mixed', Array.from(hex).map((character, index) => index % 2 ? character.toUpperCase() : character).join('')],
    ['base64', base64],
    ['base64-unpadded', base64.replace(/=+$/, '')],
    ['base64url', bytes.toString('base64url')],
    // The percent form is the longest registered rendering (three characters per byte),
    // so it sets how much emitted context a continuation must be checked against.
    ['percent-lower', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join('')],
    ['percent-upper', [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0').toUpperCase()}`).join('')],
  ];

  // Do-nothing and indiscriminate suppression both fail this preservation check.
  const ordinaryStdout = capturedSink(), ordinaryStderr = capturedSink();
  const ordinary = createOutput({ stdout: ordinaryStdout.sink, stderr: ordinaryStderr.sink, secrets: [new Secret(bytes)] });
  await ordinary.write('normal adjacent ', { stream: 'stdout', exitCode: 0 });
  await ordinary.write('message caf\u00e9.', { stream: 'stdout', exitCode: 0 });
  await ordinary.write('independent diagnostic.', { stream: 'stderr', exitCode: 0 });
  expect(ordinaryStdout.text() === 'normal adjacent message caf\u00e9.', 'ordinary completed writes preserve every adjacent byte').toBe(true);
  expect(ordinaryStderr.text() === 'independent diagnostic.', 'diagnostics stay on their selected transport').toBe(true);

  for (const [encoding, value] of representations) {
    const partitions = [
      [value.slice(0, 1), value.slice(1)],
      [value.slice(0, Math.floor(value.length / 2)), value.slice(Math.floor(value.length / 2))],
      [value.slice(0, -1), value.slice(-1)],
      [value.slice(0, 1), value.slice(1, -1), value.slice(-1)],
    ];
    for (const [partition, pieces] of partitions.entries()) {
      for (const stream of ['stdout', 'stderr'] as const) {
        const target = capturedSink(), other = capturedSink();
        const opposite = stream === 'stdout' ? 'stderr' : 'stdout';
        const output = createOutput({
          stdout: stream === 'stdout' ? target.sink : other.sink,
          stderr: stream === 'stderr' ? target.sink : other.sink,
          secrets: [new Secret(bytes)],
        });
        const label = `${encoding}/partition-${String(partition)}/${stream}`;
        await output.write(`before / ${pieces[0] ?? ''}`, { stream, exitCode: 0 });
        // Interleaving an unrelated transport must not erase this one's suffix.
        await output.write('other transport ordinary.', { stream: opposite, exitCode: 0 });
        for (const piece of pieces.slice(1)) await output.write(piece, { stream, exitCode: 0 });
        await output.write(' / after; ', { stream, exitCode: 0 });
        await output.write('normal adjacent output.', { stream, exitCode: 0 });
        const text = target.text();
        expect(representations.every(([, encoded]) => !text.includes(encoded)) && !text.toLowerCase().includes(hex), `${label}: joined writes disclose no complete registered encoding`).toBe(true);
        const surrounding = text.split(' / ');
        expect(surrounding.length === 3 && surrounding[0] === 'before' && surrounding[2] === 'after; normal adjacent output.', `${label}: ordinary surrounding and following text is byte-identical`).toBe(true);
        expect(other.text() === 'other transport ordinary.', `${label}: unrelated transport output is untouched`).toBe(true);
      }
    }

    // A prefix on stdout cannot justify censoring a harmless fragment on a
    // different transport. The two fragments do not form a credential there.
    const stdout = capturedSink(), stderr = capturedSink();
    const separated = createOutput({ stdout: stdout.sink, stderr: stderr.sink, secrets: [new Secret(bytes)] });
    const split = Math.floor(value.length / 2);
    const first = `left / ${value.slice(0, split)}`;
    const second = `${value.slice(split)} / right`;
    await separated.write(first, { stream: 'stdout', exitCode: 0 });
    await separated.write(second, { stream: 'stderr', exitCode: 0 });
    await separated.finalize();
    expect(stdout.text() === first && stderr.text() === second, `${encoding}: separate transports preserve independent partial messages`).toBe(true);
  }
});
