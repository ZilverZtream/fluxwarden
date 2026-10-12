// Test helpers: spawn the built `fluxwarden` binary as a child process and
// read repository files. Everything here goes through the public surface (the bin entry
// named in package.json, the files in the repository), never through src/ internals.
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export function readText(relativePath: string): string {
  return readFileSync(join(repoRoot, relativePath), 'utf8');
}

export function readJson(relativePath: string): unknown {
  const value: unknown = JSON.parse(readText(relativePath));
  return value;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${what} is not an object`);
  return value;
}

/** Absolute path of the bin entry package.json declares for `fluxwarden` (SPEC §2.1). */
export function binPath(): string {
  const pkg = asRecord(readJson('package.json'), 'package.json');
  const bin = pkg['bin'];
  const entry = isRecord(bin) ? bin['fluxwarden'] : undefined;
  if (typeof entry !== 'string') throw new Error('package.json has no bin.fluxwarden entry');
  return resolve(repoRoot, entry);
}

/** Scratch directory under $FLUXWARDEN_TEST_TMP when set, else under os.tmpdir(). */
export function scratchDir(prefix: string): string {
  const base = process.env['FLUXWARDEN_TEST_TMP'] ?? tmpdir();
  return mkdtempSync(join(base, `fw-cp001-${prefix}-`));
}

/** Environment for the child: the parent's, minus variables that change Node's own output. */
export function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env['NODE_OPTIONS'];
  delete env['NODE_DEBUG'];
  return env;
}

export interface CliResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

export interface RunOptions {
  /** Source of an ES module preloaded with `node --import` (process-level fault injection). */
  preloadSource?: string;
  /** Destroy the parent's end of the child's stdout pipe at once (reader gone before any write). */
  closeStdout?: boolean;
  /** Destroy the parent's end of the child's stderr pipe at once (reader gone before any write). */
  closeStderr?: boolean;
  /** Redirect the child's stdout to a regular file (not a pipe); `stdout` is the file's content after exit. */
  stdoutToFile?: boolean;
  timeoutMs?: number;
}

export function runCli(args: readonly string[], options: RunOptions = {}): Promise<CliResult> {
  const nodeArgs: string[] = [];
  if (options.preloadSource !== undefined) {
    const file = join(scratchDir('preload'), 'preload.mjs');
    writeFileSync(file, options.preloadSource, 'utf8');
    nodeArgs.push('--import', pathToFileURL(file).href);
  }
  nodeArgs.push(binPath(), ...args);
  const stdoutFile = options.stdoutToFile === true ? join(scratchDir('stdout'), 'stdout.txt') : undefined;
  return new Promise((resolvePromise, reject) => {
    const fd = stdoutFile === undefined ? undefined : openSync(stdoutFile, 'w');
    const child = spawn(process.execPath, nodeArgs, {
      cwd: scratchDir('cwd'),
      env: childEnv(),
      stdio: ['ignore', fd ?? 'pipe', 'pipe'],
      windowsHide: true,
    });
    if (fd !== undefined) closeSync(fd);
    let stdout = '';
    let stderr = '';
    if (options.closeStdout === true) child.stdout?.destroy();
    else child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
    if (options.closeStderr === true) child.stderr.destroy();
    else child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`fluxwarden did not exit within ${String(options.timeoutMs ?? 10000)} ms`));
    }, options.timeoutMs ?? 10000);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (status, signal) => {
      clearTimeout(timer);
      if (stdoutFile !== undefined) stdout = readFileSync(stdoutFile, 'utf8');
      resolvePromise({ status, signal, stdout, stderr });
    });
  });
}

/** Parses stdout as exactly one JSON document (one optional trailing newline). */
export function singleJsonDocument(stdout: string): Record<string, unknown> {
  const text = stdout.endsWith('\n') ? stdout.slice(0, -1) : stdout;
  if (text.includes('\n')) throw new Error(`stdout is not exactly one JSON document: ${JSON.stringify(stdout)}`);
  const value: unknown = JSON.parse(text);
  return asRecord(value, 'stdout document');
}

/** A V8 stack frame line: leading whitespace, then "at ". */
export const stackFrame = /^\s+at\s/m;

/** Runs `npm run --silent <script>` in the repository with the npm CLI of the running Node. */
export function runNpmScript(script: string): CliResult {
  const fromEnv = process.env['npm_execpath'];
  const npmCli = fromEnv !== undefined && /npm-cli\.js$/.test(fromEnv)
    ? fromEnv
    : process.platform === 'win32'
      ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
      : join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
  const result = spawnSync(process.execPath, [npmCli, 'run', '--silent', script], {
    cwd: repoRoot,
    env: childEnv(),
    encoding: 'utf8',
    windowsHide: true,
    timeout: 60000,
  });
  if (result.error !== undefined) throw result.error;
  return { status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr };
}
