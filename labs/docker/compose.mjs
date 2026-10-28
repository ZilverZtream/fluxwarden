import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const composeFile = fileURLToPath(new URL('./docker-compose.yml', import.meta.url));

// Docker/Compose CLI argument vectors, as in lightningnetwork/lnd@v0.21.4-beta
// docker/docker-compose-bitcoind.yml. No command or response is passed to a shell.
export function composeArguments(owner, override, args) {
  return ['--config', owner.project, 'compose', '--project-name', owner.project, '-f', composeFile,
    ...(override ? ['-f', override] : []), ...args];
}

// One environment for every Compose command of an owner, including exec and cp. The Docker
// CLI locates its compose plugin through the inherited system variables; inherited COMPOSE_*
// settings never apply, and the owner's ports are interpolated by docker-compose.yml.
export function composeEnvironment(owner, inherited = process.env) {
  return { ...Object.fromEntries(Object.entries(inherited).filter(([key]) => !/^COMPOSE_/i.test(key))), COMPOSE_PARALLEL_LIMIT: '1',
    FLUXWARDEN_LND_REST_PORT: String(owner.ports.lndRest), FLUXWARDEN_CLN_REST_PORT: String(owner.ports.clnRest),
    FLUXWARDEN_TOXIPROXY_PORT: String(owner.ports.toxiproxy) };
}

export function runProcess(argv, { cwd, env, timeoutMs, signal, stdin } = {}) {
  return new Promise((resolve, reject) => {
    if (!Array.isArray(argv) || !argv.length || argv.some(arg => typeof arg !== 'string') || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || signal?.aborted) { reject(new Error('process: invalid request')); return; }
    let child;
    const grouped = process.platform !== 'win32';
    try { child = spawn(argv[0], [...argv.slice(1)], { cwd, env, shell: false, windowsHide: true, detached: grouped, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch { reject(new Error('process: start failed')); return; }
    let stdout = [], stderr = [], captured = 0, failed = false;
    // Docker's Compose plugin cancels ongoing work on SIGTERM (docker/compose,
    // cmd/compose/compose.go AdaptCmd). Killing only its docker parent can leave
    // startup creating resources while the owner's down command removes them.
    // Own a separate POSIX process group so cancellation reaches the plugin too.
    const terminate = signal => {
      failed = true;
      if (grouped && child.pid) { try { process.kill(-child.pid, signal); } catch { /* The owned group may already have exited. */ } }
      else child.kill(signal);
    };
    const stop = () => terminate('SIGKILL');
    // Graceful cancellation followed by forced termination, as in
    // sindresorhus/execa lib/terminate/kill.js; keep the original child deadline.
    const abort = () => terminate(grouped ? 'SIGTERM' : 'SIGKILL');
    const timer = setTimeout(stop, timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    const capture = target => bytes => { captured += bytes.length; if (captured > 16 * 1024 * 1024) stop(); else target.push(bytes); };
    child.stdout.on('data', capture(stdout)); child.stderr.on('data', capture(stderr));
    child.on('error', stop); child.stdin.on('error', stop);
    child.on('close', code => {
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (failed || !Number.isInteger(code)) reject(new Error('process: interrupted'));
      else resolve({ exitCode: code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
      stdout = []; stderr = [];
    });
    if (stdin !== undefined && typeof stdin !== 'string' && !(stdin instanceof Uint8Array)) stop();
    else child.stdin.end(stdin);
  });
}

export function runDocker(argv, options) { return runProcess(['docker', ...argv], options); }
