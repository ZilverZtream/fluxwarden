// Fixed reports for the usage, interrupt and internal-error paths. None of them carries argv,
// an error message or a stack.
import { envelope, renderEnvelope, type Output } from '../output/index.js';
import { ExitCode } from './exit-codes.js';

export const USAGE = [
  'Usage: fluxwarden [--json] <command> [options]',
  '       fluxwarden keys generate --out <file>',
  '       fluxwarden --help',
  '       fluxwarden --version',
  '',
  'Policy-bound liquidity controller for LND and Core Lightning.',
  '',
  'Commands (read-only):',
  '  doctor                      Check Node.js, the database and every configured node.',
  '  nodes list                  Print the stored node rows; no node is contacted.',
  '  nodes inspect <name>        Handshake one node; --capabilities prints its capability set.',
  '  channels                    List channels, store snapshots and print deficits against the policy targets.',
  '                              --node <name>, --sort inbound-deficit|outbound|capacity',
  '  daemon --collect            Take snapshots every collect_interval until SIGINT or SIGTERM.',
  '  daemon                      Observe channels, propose rebalances and reconcile outcomes; never execute.',
  '  liquidity diagnose          Compare channel liquidity with the policy targets; --node and --horizon.',
  '  liquidity plan              Store a proposal; --refresh takes new snapshots, --policy selects a policy.',
  '  liquidity explain <id>      Print the stored proposal, route, digest and approvals.',
  '  actions status <id>         Print execution state and events; --watch follows transitions.',
  '  ledger verify               Verify journal balances and execution records.',
  '  reconcile                   Resolve outcomes and compare node accounting; --node, --since and --until.',
  '  evidence export             Export a stored reconciliation run; --run-id and --out.',
  '',
  'Approved money movement (regtest):',
  '  liquidity approve <id>      Sign a proposal with --key <file>. Optional approval caps:',
  '                              --max-fee-msat <msat>, --max-cltv-delta <blocks>, --expires-in <duration>.',
  '  actions execute <id>        Execute one approved proposal; --require-regtest is required.',
  '',
  'Disposable regtest lab (source checkout):',
  '  lab up                     Start the lab declared by FLUXWARDEN_LAB_PLAN; --seed <n>.',
  '  lab down                   Remove only the declared lab containers and volumes.',
  '  lab workload               Pay checkout invoices; --type checkout, --count <n>, --seed <n>.',
  '  lab chaos                  Run --case T-05 or --all supported cases (T-05); --seed <n>.',
  '',
  'Keys:',
  '  keys generate --out <file>  Write a new operator approval key to a new owner-only file and print its',
  '                              public key and key_id for approval_keys.',
  '',
  'Options:',
  '  --config <path>             Configuration file (default ./fluxwarden.yaml).',
  '  --url <https url>, --tls-cert-path <path>, --macaroon-path <path> | --rune-path <path>',
  '                              Connection of the one selected node, all from flags; or set FLUXWARDEN_URL,',
  '                              FLUXWARDEN_TLS_CERT_PATH and FLUXWARDEN_MACAROON_PATH | FLUXWARDEN_RUNE_PATH.',
  '                              Credentials are given by file path only.',
  '  --help     Print this help and exit.',
  '  --version  Print the version and exit.',
  '  --json     Print exactly one JSON document on stdout.',
  '',
].join('\n');

export function reportUsageError(output: Output, json: boolean, reason: string, command: string | null = null): void {
  if (json) {
    const message = `${reason}; usage: fluxwarden [--json] <command> [options]; see fluxwarden --help`;
    output.write('stdout', renderEnvelope(envelope(command, null, { code: ExitCode.INVALID_INPUT, step: null, message })));
  } else {
    output.write('stderr', `fluxwarden: ${reason}\n\n${USAGE}`);
  }
}

/** A command's own refusal; the message is fixed text and never carries argv. */
export function reportCommandError(output: Output, json: boolean, command: string, code: ExitCode, message: string): void {
  if (json) output.write('stdout', renderEnvelope(envelope(command, null, { code, step: null, message })));
  else output.write('stderr', `fluxwarden: ${message}\n`);
}

export function reportInternal(output: Output, json: boolean, done: () => void): void {
  const message = 'internal error';
  if (json) {
    output.write('stdout', renderEnvelope(envelope(null, null, { code: ExitCode.INVARIANT_BREACH, step: 'internal', message })), done);
  } else {
    output.write('stderr', `fluxwarden: ${message}\n`, done);
  }
}

export function reportInterrupted(output: Output, json: boolean, done: () => void): void {
  const message = 'interrupted';
  if (json) {
    output.write('stdout', renderEnvelope(envelope(null, null, { code: ExitCode.INTERRUPTED, step: null, message })), done);
  } else {
    output.write('stderr', `fluxwarden: ${message}\n`, done);
  }
}
