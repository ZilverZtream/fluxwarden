// The built CLI is exercised as a child process. Expected exit codes and envelopes follow
// the public output specification: 0 SUCCESS, 2 INVALID_INPUT, 6 INTERRUPTED, 8 INVARIANT_BREACH.
// Internal failures take precedence over interrupts and the command exit code.
import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { asRecord, binPath, readJson, runCli, singleJsonDocument, stackFrame, type CliResult } from '../helpers/cli.js';

const SUCCESS = 0;
const INVALID_INPUT = 2;
const INTERRUPTED = 6;
const INVARIANT_BREACH = 8;
const packageVersion = asRecord(readJson('package.json'), 'package.json')['version'];
if (typeof packageVersion !== 'string' || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(packageVersion)) throw new Error('package.json has no valid version');

/** Keep-alive timer in the child for the "the run ends" cases; a run that does not end itself lasts this long. */
const KEEP_ALIVE_MS = 8000;
/** "At once" / "promptly": well within KEEP_ALIVE_MS, including process start-up on a slow CI runner. */
const PROMPT_MS = 3000;
const keepAlive = `setTimeout(() => {}, ${String(KEEP_ALIVE_MS)});\n`;
/** Linux: a real signal to the child; Windows cannot deliver a catchable signal, so the event is emitted inside the child. */
const deliverSignal = (sig: string): string => process.platform === 'win32'
  ? `process.emit(${JSON.stringify(sig)}, ${JSON.stringify(sig)})`
  : `process.kill(process.pid, ${JSON.stringify(sig)})`;

/** Runs the CLI and measures the wall time from spawn to exit. */
async function timedRun(args: readonly string[], options: Parameters<typeof runCli>[1]): Promise<{ r: CliResult; ms: number }> {
  const start = Date.now();
  const r = await runCli(args, options);
  return { r, ms: Date.now() - start };
}

const marker = (): string => `mk${randomBytes(8).toString('hex')}`;

/** "Usage text naming the binary" (B2, B3, B4). */
function expectUsage(text: string): void {
  expect(text).toMatch(/usage/i);
  expect(text).toMatch(/\bfluxwarden\b/);
}

function errorOf(doc: Record<string, unknown>): Record<string, unknown> {
  return asRecord(doc['error'], 'error');
}

/**
 * Process-level fault injection, preloaded with `node --import`: the first write the CLI makes
 * to stdout or stderr (stream write, console, or fs.writeSync on fd 1/2) does not happen and
 * `fault` runs instead. Later writes pass through. Production code needs no test hook for this.
 */
function faultOnFirstWrite(fault: string): string {
  return [
    "import fs from 'node:fs';",
    "import { syncBuiltinESMExports } from 'node:module';",
    'let fired = false;',
    "const done = (args) => { const cb = args.find((a) => typeof a === 'function'); if (cb) process.nextTick(cb); return true; };",
    `const fault = (args) => { ${fault}; return done(args); };`,
    'for (const stream of [process.stdout, process.stderr]) {',
    '  const original = stream.write;',
    '  stream.write = function (...args) {',
    '    if (!fired) { fired = true; return fault(args); }',
    '    return original.apply(this, args);',
    '  };',
    '}',
    'const originalWriteSync = fs.writeSync;',
    'fs.writeSync = function (fd, ...rest) {',
    "  if ((fd === 1 || fd === 2) && !fired) { fired = true; fault([]); return typeof rest[0] === 'string' ? Buffer.byteLength(rest[0]) : rest[0].length; }",
    '  return originalWriteSync.call(fs, fd, ...rest);',
    '};',
    'syncBuiltinESMExports();',
    '',
  ].join('\n');
}

/**
 * Like faultOnFirstWrite, and the write after it (the first signal's interrupt report) is stalled:
 * it is swallowed and its callback never runs, so nothing that waits for that write can end the
 * process. Writes after that pass through, so a second report would be visible.
 */
function faultThenStallReport(fault: string): string {
  return [
    "import fs from 'node:fs';",
    "import { syncBuiltinESMExports } from 'node:module';",
    'let writes = 0;',
    "const done = (args) => { const cb = args.find((a) => typeof a === 'function'); if (cb) process.nextTick(cb); return true; };",
    `const fault = (args) => { ${fault}; return done(args); };`,
    'for (const stream of [process.stdout, process.stderr]) {',
    '  const original = stream.write;',
    '  stream.write = function (...args) {',
    '    writes += 1;',
    '    if (writes === 1) return fault(args);',
    '    if (writes === 2) return true;',
    '    return original.apply(this, args);',
    '  };',
    '}',
    'const originalWriteSync = fs.writeSync;',
    'fs.writeSync = function (fd, ...rest) {',
    '  if (fd === 1 || fd === 2) {',
    '    writes += 1;',
    "    const size = typeof rest[0] === 'string' ? Buffer.byteLength(rest[0]) : rest[0].length;",
    '    if (writes === 1) { fault([]); return size; }',
    '    if (writes === 2) return size;',
    '  }',
    '  return originalWriteSync.call(fs, fd, ...rest);',
    '};',
    'syncBuiltinESMExports();',
    '',
  ].join('\n');
}

/**
 * Preload that lets the CLI's first write to stdout or stderr happen and then runs `after` once,
 * right after that write was handed off (the command has produced its output).
 */
function afterFirstWrite(after: string): string {
  return [
    "import fs from 'node:fs';",
    "import { syncBuiltinESMExports } from 'node:module';",
    'let fired = false;',
    `const after = () => { if (fired) return; fired = true; ${after}; };`,
    'for (const stream of [process.stdout, process.stderr]) {',
    '  const original = stream.write;',
    '  stream.write = function (...args) { const r = original.apply(this, args); after(); return r; };',
    '}',
    'const originalWriteSync = fs.writeSync;',
    'fs.writeSync = function (fd, ...rest) {',
    '  const r = originalWriteSync.call(fs, fd, ...rest);',
    '  if (fd === 1 || fd === 2) after();',
    '  return r;',
    '};',
    'syncBuiltinESMExports();',
    '',
  ].join('\n');
}

/**
 * Preload that turns stdout and stderr into slow but healthy asynchronous streams: every write is handed
 * to the real stream only `delayMs` later, in order, and its callback runs then (as on a pipe whose
 * writes complete asynchronously). `after` runs once, right after the CLI's first write
 * was queued (the command has produced its output, none of it delivered yet).
 */
function slowAsyncStreams(delayMs: number, after: string): string {
  return [
    'let queue = Promise.resolve();',
    'let fired = false;',
    `const after = () => { if (fired) return; fired = true; ${after}; };`,
    'for (const stream of [process.stdout, process.stderr]) {',
    '  const original = stream.write.bind(stream);',
    '  stream.write = function (chunk, encoding, callback) {',
    "    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }",
    `    queue = queue.then(() => new Promise((resolve) => setTimeout(() => { original(chunk, encoding); resolve(); if (callback) callback(); }, ${String(delayMs)})));`,
    '    after();',
    '    return true;',
    '  };',
    '}',
    '',
  ].join('\n');
}

/** Source that throws an Error whose message carries the marker and the child's whole argv. */
const throwWith = (m: string): string => `throw new Error(${JSON.stringify(m)} + ' ' + process.argv.join(' '))`;
/** Source that leaves a rejected promise unhandled; the reason carries the marker and argv. */
const rejectWith = (m: string): string => `void Promise.reject(new Error(${JSON.stringify(m)} + ' ' + process.argv.join(' ')))`;
/** Runs `source` on a later tick, after the CLI's synchronous call has returned. */
const later = (source: string): string => `setImmediate(() => { ${source}; })`;
/** Emits the signal event inside the child: the deterministic interleaving point for the B8 orderings. */
const emitSignal = (sig: string): string => `process.emit(${JSON.stringify(sig)}, ${JSON.stringify(sig)})`;

/**
 * Exit-8 output: no marker, argv element or stack frame anywhere; in text mode stdout is
 * empty and the report is on stderr; with --json stdout holds exactly one document with code 8, step "internal".
 */
function expectBreachReport(r: CliResult, json: boolean, label: string, secrets: readonly string[]): void {
  expect({ status: r.status, signal: r.signal }, label).toEqual({ status: INVARIANT_BREACH, signal: null });
  const output = r.stdout + r.stderr;
  for (const secret of secrets) expect(output, label).not.toContain(secret);
  const bin = binPath();
  expect(output, label).not.toContain(bin);
  expect(output, label).not.toContain(bin.replace(/\\/g, '/'));
  expect(output, label).not.toContain(process.execPath);
  expect(output, label).not.toMatch(stackFrame);
  if (json) {
    const doc = singleJsonDocument(r.stdout);
    expect(doc['ok'], label).toBe(false);
    expect(errorOf(doc), label).toMatchObject({ code: 8, step: 'internal' });
  } else {
    expect(r.stdout, `${label}: text-mode stdout`).toBe('');
    expect(r.stderr.trim(), `${label}: text-mode report on stderr`).not.toBe('');
  }
}

// Bug caught: version read from the wrong place, printed without newline, or on stderr.
it('CP-001/B1 --version prints exactly the package version and a newline on stdout and exits 0', async () => {
  const r = await runCli(['--version']);
  expect(r).toEqual({ status: SUCCESS, signal: null, stdout: `${packageVersion}\n`, stderr: '' });
});

// Bug caught: help printed on stderr or treated as a usage error (exit 2).
it('CP-001/B2 --help prints usage naming fluxwarden on stdout, nothing on stderr, exit 0', async () => {
  const r = await runCli(['--help']);
  expect(r.status).toBe(SUCCESS);
  expect(r.stderr).toBe('');
  expectUsage(r.stdout);
});

// Bug caught: a run without arguments prints help on stdout and exits 0 instead of a usage error.
it('CP-001/B3 no arguments prints usage on stderr, nothing on stdout, exit 2', async () => {
  const r = await runCli([]);
  expect(r.status).toBe(INVALID_INPUT);
  expect(r.stdout).toBe('');
  expectUsage(r.stderr);
});

// Bug caught: "unknown command 'x'" style messages that echo the offending token (FC-129).
it('CP-001/B4 an unknown command and an unknown flag exit 2 with usage on stderr and are never echoed', async () => {
  const m = marker();
  for (const token of [`zzcmd${m}`, `--zzflag${m}`]) {
    const r = await runCli([token]);
    expect(r.status, token).toBe(INVALID_INPUT);
    expectUsage(r.stderr);
    expect(r.stdout + r.stderr, token).not.toContain(m);
  }
});

// Bug caught: envelope with ok:true, command "" instead of null, missing or extra fields, text mixed into stdout.
it('CP-001/B5 --json alone prints exactly one envelope with command null and error.code 2, exit 2', async () => {
  const r = await runCli(['--json']);
  expect(r.status).toBe(INVALID_INPUT);
  const doc = singleJsonDocument(r.stdout);
  expect(doc).toEqual({
    schema: 1, command: null, ok: false, warnings: [], result: null,
    error: { code: 2, step: null, message: expect.any(String) as unknown },
  });
  // SPEC §10.1: ok is false exactly when error is not null.
  expect(String(errorOf(doc)['message']).length).toBeGreaterThan(0);
});

// Bug caught: --json ignored by --help or --version (plain text on stdout), or a second document.
it('CP-001/B5 --json --help and --json --version print exactly one ok:true envelope with the package version and exit 0', async () => {
  const help = await runCli(['--json', '--help']);
  expect(help.status).toBe(SUCCESS);
  expect(help.stderr).toBe('');
  expect(singleJsonDocument(help.stdout)).toMatchObject({ schema: 1, ok: true, warnings: [], error: null });

  const version = await runCli(['--json', '--version']);
  expect(version.status).toBe(SUCCESS);
  expect(version.stderr).toBe('');
  expect(singleJsonDocument(version.stdout)).toMatchObject({ schema: 1, ok: true, warnings: [], result: { version: packageVersion }, error: null });
});

// Bug caught: --help/--version winning over a stray token (exit 0 hides a typo), or a "--" after "--"
// taken as a second separator instead of an operand (every token after the first "--" is an operand).
it('CP-001/B5 --help or --version with an unknown flag, an unknown operand or an operand after "--" exit 2 and echo nothing', async () => {
  const m = marker();
  const argSets = [
    ['--help', `--zzflag${m}`],
    ['--version', `--zzflag${m}`],
    ['--help', `zzop${m}`],
    [`zzop${m}`, '--version'],
    ['--help', '--', `zzop${m}`],
    ['--version', '--', '--'],
    ['--json', '--version', '--', '--'],
    ['--json', '--help', `zzop${m}`],
  ];
  for (const args of argSets) {
    const r = await runCli(args);
    const label = args.join(' ');
    expect(r.status, label).toBe(INVALID_INPUT);
    expect(r.stdout + r.stderr, label).not.toContain(m);
    if (args.includes('--json')) expect(errorOf(singleJsonDocument(r.stdout))['code'], label).toBe(2);
    else expect(r.stdout, label).toBe('');
  }
});

// Bug caught: a credential-shaped argument echoed whole, truncated, upper-cased or re-encoded (FC-111, FC-129).
it('CP-001/B6 a 64-hex command or flag value is never echoed in any form, text or --json, exit 2', async () => {
  const bytes = randomBytes(32);
  const hex = bytes.toString('hex');
  const forms = [hex, hex.toUpperCase(), bytes.toString('base64'), bytes.toString('base64url')];
  const argSets = [[hex], ['--json', hex], ['--zzflag', hex], [`--zzflag=${hex}`], ['--json', '--zzflag', hex]];
  for (const args of argSets) {
    const r = await runCli(args);
    const label = args.map(a => a.replace(hex, '<64hex>')).join(' ');
    expect(r.status, label).toBe(INVALID_INPUT);
    if (args.includes('--json')) expect(errorOf(singleJsonDocument(r.stdout))['code'], label).toBe(2);
    const output = r.stdout + r.stderr;
    for (const form of forms) {
      for (let i = 0; i + 16 <= form.length; i += 1) {
        if (output.includes(form.slice(i, i + 16))) {
          throw new Error(`${label}: a 16-character window of the 64-hex argument (offset ${String(i)}) appears in the output`);
        }
      }
    }
  }
});

const failures = [
  { name: 'an exception', raise: throwWith },
  { name: 'an unhandled promise rejection', raise: rejectWith },
];
for (const failure of failures) {
  // Bug caught: the default Node crash (stack with message and paths, exit 1) because a process-level
  // handler is missing; a handler that echoes error.message (which carries argv); a failure swallowed
  // so the run exits 0 or 2; the text-mode report written to stdout (FC-123).
  it(`CP-001/B7 ${failure.name} during command handling or on a later tick exits 8 with no marker, argv or stack; text report on stderr only; --json one document with code 8, step "internal"`, async () => {
    const argvToken = `zzargv${marker()}`;
    const cases = [
      { args: ['--version'], json: false },
      { args: [argvToken], json: false },
      { args: ['--json'], json: true },
      { args: ['--json', argvToken], json: true },
    ];
    for (const timing of ['during', 'later'] as const) {
      for (const c of cases) {
        const m = marker();
        const raise = timing === 'during' ? failure.raise(m) : later(failure.raise(m));
        const r = await runCli(c.args, { preloadSource: faultOnFirstWrite(raise) });
        expectBreachReport(r, c.json, `${timing}: ${c.args.join(' ')}`, [m, argvToken]);
      }
    }
  });
}

// Bug caught: with stdout redirected to a file (a stream without a byte counter), a document write that
// threw still counts as "the document is out", so the exit-8 document is suppressed and the file is
// empty. The exception is thrown out of the CLI's own --json write,
// so nothing reached the file before the internal-error document.
it('CP-001/B7 an exception thrown out of the --json document write, with stdout redirected to a file, leaves exactly one document with code 8, step "internal", exit 8', async () => {
  const argvToken = `zzargv${marker()}`;
  for (const args of [['--json'], ['--json', '--version'], ['--json', argvToken]]) {
    const m = marker();
    const r = await runCli(args, { preloadSource: faultOnFirstWrite(throwWith(m)), stdoutToFile: true });
    expectBreachReport(r, true, `${args.join(' ')}, stdout to a file`, [m, argvToken]);
  }
});

// Bug caught: the exit-8 handler reporting every failure (no once guard), or forgetting a breach the
// command already reported, so a later failure prints a second report or a second JSON document; two
// failures handled in the same tick in text mode, before the first report's write has completed, each
// printing an internal-error line.
it('CP-001/B7 two failures (two late ones, one in command handling and one later, or two in the same tick) produce one report and exit 8', async () => {
  const pairs = [
    { name: 'two late failures', single: (m: string) => later(throwWith(m)), pair: (m: string) => `${later(throwWith(m))}; ${later(rejectWith(m))}` },
    { name: 'in-command then late', single: (m: string) => throwWith(m), pair: (m: string) => `${later(throwWith(m))}; ${throwWith(m)}` },
    { name: 'two rejections, same tick', single: (m: string) => rejectWith(m), pair: (m: string) => `${rejectWith(m)}; ${rejectWith(m)}` },
  ];
  for (const p of pairs) {
    for (const args of [['--version'], ['--json', '--version']]) {
      const json = args.includes('--json');
      const label = `${p.name}: ${args.join(' ')}`;
      const m = marker();
      const twice = await runCli(args, { preloadSource: faultOnFirstWrite(p.pair(m)) });
      expectBreachReport(twice, json, label, [m]);
      if (!json) {
        // One report: the text output of two failures equals the output of the first one alone.
        const once = await runCli(args, { preloadSource: faultOnFirstWrite(p.single(m)) });
        expect(twice.stderr, label).toBe(once.stderr);
      }
    }
  }
});

// Bug caught: the exit-8 path waiting for the internal-error report's write callback. A stalled
// report must not leave the run alive or let the timer already pending at the failure write output.
// The report write is swallowed and its callback never runs; the pending timer fires after 300 ms.
it('CP-001/B7 an internal error whose report write never completes still ends the run promptly with exit 8, and a timer pending at the failure never runs', async () => {
  const lateTimer = `zzlatetimer${marker()}`;
  const pending = `setTimeout(() => { process.stderr.write(${JSON.stringify(`${lateTimer}\n`)}); }, 300)`;
  for (const failure of failures) {
    for (const args of [['--version'], ['--json', '--version']]) {
      const m = marker();
      const label = `${failure.name}, report stalled: ${args.join(' ')}`;
      const preload = keepAlive + faultThenStallReport(`${pending}; ${failure.raise(m)}`);
      const { r, ms } = await timedRun(args, { preloadSource: preload, timeoutMs: KEEP_ALIVE_MS + 4000 });
      expect({ status: r.status, signal: r.signal }, label).toEqual({ status: INVARIANT_BREACH, signal: null });
      expect(ms, `${label}: ended ${String(ms)} ms after spawn`).toBeLessThan(PROMPT_MS);
      expect(r.stdout + r.stderr, `${label}: the pending timer ran`).not.toContain(lateTimer);
      expect(r.stdout + r.stderr, label).not.toContain(m);
      expect(r.stdout + r.stderr, label).not.toMatch(stackFrame);
    }
  }
}, 60_000);

// Bug caught: no SIGINT/SIGTERM handler (killed by the signal, no exit code), a handler exiting 0, 1 or 130,
// or the text-mode interrupt line written to stdout.
it('CP-001/B8 SIGINT and SIGTERM before any mutating call exit 6; text line on stderr; --json gives error.code 6', async () => {
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    // Linux: a real signal to the child process. Windows cannot deliver a catchable signal to a
    // process, so there the signal event is injected inside the child.
    const deliver = process.platform === 'win32' ? `setImmediate(() => ${emitSignal(sig)})` : `process.kill(process.pid, ${JSON.stringify(sig)})`;
    // The signal arrives in place of the CLI's first output, before anything was printed. A bounded
    // timer keeps the process alive for the handler, whether it calls process.exit or sets exitCode.
    const preload = `setTimeout(() => {}, 3000);\n${faultOnFirstWrite(deliver)}`;
    for (const args of [['--help'], ['--json']]) {
      const r = await runCli(args, { preloadSource: preload });
      const label = `${sig} ${args.join(' ')}`;
      expect({ status: r.status, signal: r.signal }, label).toEqual({ status: INTERRUPTED, signal: null });
      expect(r.stdout + r.stderr, label).not.toMatch(stackFrame);
      if (args.includes('--json')) {
        const doc = singleJsonDocument(r.stdout);
        expect(doc['ok'], label).toBe(false);
        expect(errorOf(doc)['code'], label).toBe(6);
      } else {
        expect(r.stdout, label).toBe('');
        expect(r.stderr.trim(), label).not.toBe('');
      }
    }
  }
});

// Bug caught: an interrupt waiting indefinitely for a stalled report's write callback. Later
// writes pass through, so a second signal would expose an erroneous second report.
it('CP-001/B8 a SIGINT or SIGTERM whose interrupt report write never completes still ends the run promptly with exit 6, and a second signal writes no second report', async () => {
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    const deliveries = [
      { name: 'one signal', fault: deliverSignal(sig) },
      { name: 'two signals', fault: `${emitSignal(sig)}; setImmediate(() => { ${deliverSignal(sig)}; })` },
    ];
    for (const d of deliveries) {
      for (const args of [['--help'], ['--json']]) {
        const label = `${sig}, ${d.name}, report stalled: ${args.join(' ')}`;
        const preload = keepAlive + faultThenStallReport(d.fault);
        const { r, ms } = await timedRun(args, { preloadSource: preload, timeoutMs: KEEP_ALIVE_MS + 4000 });
        expect({ status: r.status, signal: r.signal }, label).toEqual({ status: INTERRUPTED, signal: null });
        expect(ms, `${label}: ended ${String(ms)} ms after spawn`).toBeLessThan(PROMPT_MS);
        // The stalled first report never reached a stream; any output would be a second report.
        expect({ stdout: r.stdout, stderr: r.stderr }, label).toEqual({ stdout: '', stderr: '' });
      }
    }
  }
}, 60_000);

// Bug caught: the interrupt deciding the exit code over a breach (exit 6 where an internal failure requires 8),
// in either order, or both reports written as two JSON documents; the interrupt exit firing before a
// rejection raised in the same tick as the signal is processed.
it('CP-001/B8 an internal error after a signal and a signal after an internal error both exit 8', async () => {
  const orders = [
    { name: 'signal after error', fault: (sig: string, m: string) => `${later(throwWith(m))}; setImmediate(() => ${emitSignal(sig)})` },
    { name: 'error after signal', fault: (sig: string, m: string) => `${emitSignal(sig)}; ${throwWith(m)}` },
    // A rejection raised in the same tick as the first signal, after it and before it.
    { name: 'rejection after signal, same tick', fault: (sig: string, m: string) => `${emitSignal(sig)}; ${rejectWith(m)}` },
    { name: 'rejection before signal, same tick', fault: (sig: string, m: string) => `${rejectWith(m)}; ${emitSignal(sig)}` },
  ];
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    for (const order of orders) {
      for (const args of [['--version'], ['--json', '--version']]) {
        const m = marker();
        const label = `${order.name} (${sig}): ${args.join(' ')}`;
        const r = await runCli(args, { preloadSource: keepAlive + faultOnFirstWrite(order.fault(sig, m)), timeoutMs: KEEP_ALIVE_MS + 4000 });
        expect({ status: r.status, signal: r.signal }, label).toEqual({ status: INVARIANT_BREACH, signal: null });
        expect(r.stdout + r.stderr, label).not.toContain(m);
        expect(r.stdout + r.stderr, label).not.toMatch(stackFrame);
        if (args.includes('--json')) singleJsonDocument(r.stdout);
      }
    }
  }
}, 60_000);

// Bug caught: a late signal or failure appending a second JSON document or leaving the process
// alive until the keep-alive timer. Pipe and file output both preserve exactly one document.
it('CP-001/B8 after the package version JSON document is written, a late signal ends the run promptly with exit 6 and a late failure ends it promptly with exit 8; one document on a pipe and in a file', async () => {
  const versionDoc = { schema: 1, command: null, ok: true, warnings: [], result: { version: packageVersion }, error: null };
  const m = marker();
  const cases = [
    // Each must end the run itself: the keep-alive timer would otherwise hold the process open
    // (signals and internal errors both require prompt termination).
    { name: 'SIGINT', after: `setImmediate(() => { ${deliverSignal('SIGINT')}; })`, expected: INTERRUPTED },
    { name: 'SIGTERM', after: `setImmediate(() => { ${deliverSignal('SIGTERM')}; })`, expected: INTERRUPTED },
    { name: 'exception', after: later(throwWith(m)), expected: INVARIANT_BREACH },
    { name: 'rejection', after: later(rejectWith(m)), expected: INVARIANT_BREACH },
  ];
  for (const c of cases) {
    for (const stdoutToFile of [false, true]) {
      const label = `${c.name}, stdout to ${stdoutToFile ? 'a file' : 'a pipe'}`;
      const { r, ms } = await timedRun(['--json', '--version'], {
        preloadSource: keepAlive + afterFirstWrite(c.after), stdoutToFile, timeoutMs: KEEP_ALIVE_MS + 4000,
      });
      expect({ status: r.status, signal: r.signal }, label).toEqual({ status: c.expected, signal: null });
      expect(ms, `${label}: ended ${String(ms)} ms after spawn`).toBeLessThan(PROMPT_MS);
      expect(singleJsonDocument(r.stdout), label).toEqual(versionDoc);
      expect(r.stdout + r.stderr, label).not.toContain(m);
      expect(r.stdout + r.stderr, label).not.toMatch(stackFrame);
    }
  }
}, 90_000);

// Bug caught: a late text-mode failure exiting silently after --help, or leaving the process
// alive until the keep-alive timer. Its internal-error report must reach stderr before exit.
it('CP-001/B7 after text --help output, a late exception or rejection ends the run promptly with exit 8, the help text on stdout and the internal-error report on stderr', async () => {
  const help = await runCli(['--help']);
  expect(help.status).toBe(SUCCESS);
  for (const failure of failures) {
    const m = marker();
    const { r, ms } = await timedRun(['--help'], { preloadSource: keepAlive + afterFirstWrite(later(failure.raise(m))), timeoutMs: KEEP_ALIVE_MS + 4000 });
    expect({ status: r.status, signal: r.signal }, failure.name).toEqual({ status: INVARIANT_BREACH, signal: null });
    expect(ms, `${failure.name}: ended ${String(ms)} ms after spawn`).toBeLessThan(PROMPT_MS);
    expect(r.stdout, failure.name).toBe(help.stdout);
    expect(r.stderr.trim(), `${failure.name}: internal-error report on stderr`).not.toBe('');
    expect(r.stdout + r.stderr, failure.name).not.toContain(m);
    expect(r.stdout + r.stderr, failure.name).not.toMatch(stackFrame);
  }
}, 60_000);

// Bug caught: a fallback exit cutting off output from a healthy asynchronous stream taking
// 20 ms per write. Help and the report must reach stdout and stderr before exit 6 or 8.
// The expected help text is what an undisturbed --help run prints.
it('CP-001/B8 with stdout and stderr as asynchronous streams taking 20 ms per write, a late signal (exit 6) or late internal error (exit 8) after --help still delivers the whole help text and the report', async () => {
  const help = await runCli(['--help']);
  expect(help.status).toBe(SUCCESS);
  const m = marker();
  const cases = [
    { name: 'late SIGINT', late: `setImmediate(() => { ${deliverSignal('SIGINT')}; })`, expected: INTERRUPTED },
    { name: 'late SIGTERM', late: `setImmediate(() => { ${deliverSignal('SIGTERM')}; })`, expected: INTERRUPTED },
    { name: 'late exception', late: later(throwWith(m)), expected: INVARIANT_BREACH },
    { name: 'late rejection', late: later(rejectWith(m)), expected: INVARIANT_BREACH },
  ];
  for (const c of cases) {
    const { r, ms } = await timedRun(['--help'], { preloadSource: keepAlive + slowAsyncStreams(20, c.late), timeoutMs: KEEP_ALIVE_MS + 4000 });
    expect({ status: r.status, signal: r.signal }, c.name).toEqual({ status: c.expected, signal: null });
    expect(ms, `${c.name}: ended ${String(ms)} ms after spawn`).toBeLessThan(PROMPT_MS);
    expect(r.stdout, `${c.name}: help text on stdout`).toBe(help.stdout);
    expect(r.stderr.trim(), `${c.name}: report on stderr`).not.toBe('');
    expect(r.stdout + r.stderr, c.name).not.toContain(m);
    expect(r.stdout + r.stderr, c.name).not.toMatch(stackFrame);
  }
}, 60_000);

// Bug caught: the EPIPE 'error' event is unhandled, so Node prints a stack and the exit code becomes 1 or 8.
it('CP-001/B15 with stdout closed by the reader, --help still exits 0 and --json still exits 2, without a stack', async () => {
  const cases: [string[], number][] = [[['--help'], SUCCESS], [['--json'], INVALID_INPUT]];
  for (const [args, expected] of cases) {
    const r = await runCli(args, { closeStdout: true });
    const label = args.join(' ');
    expect(r.status, label).toBe(expected);
    expect(r.stderr, label).not.toMatch(stackFrame);
    expect(r.stderr, label).not.toMatch(/EPIPE/);
  }
});

// Bug caught: only stdout's stream errors are handled, so a usage error written to a closed stderr
// becomes an uncaught EPIPE (exit 8 or a crash) instead of exit 2.
it('CP-001/B15 with stderr closed by the reader, a usage-error run still exits 2 with nothing on stdout', async () => {
  for (const args of [[], [`--zzflag${marker()}`]]) {
    const r = await runCli(args, { closeStderr: true });
    const label = args.length === 0 ? '(no arguments)' : '--zzflag';
    expect({ status: r.status, signal: r.signal }, label).toEqual({ status: INVALID_INPUT, signal: null });
    expect(r.stdout, label).toBe('');
  }
});
