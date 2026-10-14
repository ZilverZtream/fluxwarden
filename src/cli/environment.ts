// Refusals that run before any configuration or credential is read: credential values on the command
// line (SECURITY.md §3.3), and environment variables or Node options that load code or print request data
// (SPEC.md §10.1 ENV check). Messages name the variable or option, never a value.

/** Node modules whose NODE_DEBUG output includes request headers or bodies (SPEC.md §10.1). */
const NETWORK_DEBUG = ['http', 'https', 'tls', 'net'];

/**
 * Node and V8 options that open a debugger, write profiles, heap snapshots, reports, traces or V8 logs, or
 * log TLS session keys. Matched on the option name with `_` read as `-`, by prefix.
 */
const DIAGNOSTIC_OPTIONS = [
  '--inspect', '--debug', '--cpu-prof', '--heap-prof', '--heapsnapshot', '--report', '--diagnostic-dir', '--trace-event', '--trace-events',
  '--prof', '--log', '--logfile', '--perf-basic-prof', '--perf-prof', '--tls-keylog', '--experimental-network-inspection',
  '--interpreted-frames-native-stack',
];

/** Whether one NODE_DEBUG section (Node's `*` wildcard, any letter case) selects a network module. */
function selectsNetwork(section: string): boolean {
  const pattern = new RegExp(`^${section.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`, 'i');
  return NETWORK_DEBUG.some(name => pattern.test(name));
}

/** The first environment refusal, or null. Variable names match in any letter case. */
export function environmentRefusal(env: Readonly<Record<string, string | undefined>>, execArgv: readonly string[]): string | null {
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if (/^node_options$/i.test(key) && value.trim() !== '') return 'NODE_OPTIONS is set; unset it before running fluxwarden';
    if (/^node_debug$/i.test(key) && value.split(/[\s,]+/).some(section => section !== '' && selectsNetwork(section))) {
      return 'NODE_DEBUG names a network module (http, https, tls or net); unset it before running fluxwarden';
    }
  }
  for (const option of execArgv) {
    if (!option.startsWith('--')) continue;
    const name = (option.split('=')[0] ?? option).replace(/_/g, '-');
    if (DIAGNOSTIC_OPTIONS.some(prefix => name === prefix || name.startsWith(`${prefix}-`))) {
      return `the Node option ${name} writes diagnostics that can hold credentials; run fluxwarden without it`;
    }
  }
  return null;
}

const HEX_RUN = /[0-9a-fA-F]{64,}/;
const BASE64_RUN = /[A-Za-z0-9+_=-]{43,}/g;
const MACAROON_BASE64 = /(?:^|[^A-Za-z0-9+/])AgE[A-Za-z0-9+/_-]{40,}/;
const PRIVATE_KEY = /PRIVATE KEY|-----BEGIN /;

/**
 * Whether a command-line argument looks like a credential value (SECURITY.md §3.3): a hex run of at least
 * 32 bytes, a base64 or base64url run of at least 32 bytes mixing upper case, lower case and digits (macaroons,
 * runes, keys), a base64 macaroon, or a PEM private key.
 */
export function looksLikeCredential(argument: string): boolean {
  if (HEX_RUN.test(argument) || MACAROON_BASE64.test(argument) || PRIVATE_KEY.test(argument)) return true;
  for (const match of argument.matchAll(BASE64_RUN)) {
    const run = match[0];
    if (/[A-Z]/.test(run) && /[a-z]/.test(run) && /[0-9]/.test(run)) return true;
  }
  return false;
}
