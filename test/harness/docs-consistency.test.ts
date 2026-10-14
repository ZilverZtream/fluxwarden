// The public documentation set agrees with the command line, the exit codes, the configuration and
// policy loaders and the output schemas. Expected commands, flags, exit codes and keys come from the
// public specification (commands §10.3, exit codes §10.2, configuration §10.1, policy §7.1, runbook
// subjects §6.5, §7.7, §8.4-§8.6, §5.2 H3, §11.3); the documents and the built binary must match them.
//
// Interface:
// - `fluxwarden --help` lists every command of `COMMANDS` and every flag of `FLAGS`.
// - docs/spec.md holds the exit-code table as Markdown rows `| **<code>** | \`<LABEL>\` | ... |`;
//   README.md lists the exit codes in rows of the same form.
// - docs/spec.md holds one fenced `yaml` block starting with the line `# fluxwarden configuration` (a
//   complete configuration with one `lnd` and one `cln` node) and one starting with
//   `# fluxwarden policy` (a complete policy; `exclude_channels` may be commented out).
// - Runbooks: docs/runbooks/{unknown-recovery,stuck-in-flight,stuck-lease,policy-rollout,
//   lab-troubleshooting,key-rotation,quarantine}.md, each linked from docs/runbooks/README.md.
// - docs/references/failure-catalogue.md has a `## ... Maintenance` heading.
// - docs/references.md: references are list items; each one outside the Positioning section carries an
//   https source link.
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { ExitCode } from '../../src/core/exit-codes.js';
import { loadConfig } from '../../src/config/config.js';
import { loadPolicy } from '../../src/policy/load.js';
import { asRecord, readText, repoRoot, runCli, scratchDir } from '../helpers/cli.js';

// SPEC §10.3, ledger verification §9.5 and daemon §10.4. Lab commands are listed but never run here (they drive Docker).
const COMMANDS = [
  'doctor', 'nodes list', 'nodes inspect', 'channels', 'liquidity diagnose', 'liquidity plan', 'liquidity explain',
  'liquidity approve', 'actions execute', 'actions status', 'ledger verify', 'reconcile', 'evidence export', 'lab up', 'lab down',
  'lab workload', 'lab chaos', 'keys generate', 'daemon',
] as const;
// Flags named by SPEC §10.1 and §10.3.
const FLAGS = [
  '--config', '--json', '--help', '--version', '--capabilities', '--node', '--sort', '--horizon', '--policy', '--refresh',
  '--key', '--max-fee-msat', '--max-cltv-delta', '--expires-in', '--require-regtest', '--watch', '--since', '--run-id',
  '--out', '--seed', '--type', '--count', '--all',
];
// SPEC §10.2.
const EXIT_CODES: Record<number, string> = {
  0: 'SUCCESS', 1: 'POLICY_VIOLATION', 2: 'INVALID_INPUT', 3: 'CAPABILITY_UNSUPPORTED', 4: 'NODE_UNREACHABLE',
  5: 'SAFETY_REFUSAL', 6: 'INTERRUPTED', 7: 'OUTCOME_UNKNOWN', 8: 'INVARIANT_BREACH', 9: 'RECONCILIATION_ALERT',
};
// SPEC §7.1 policy keys (every mapping key of the reference policy except operator target names).
const POLICY_KEYS = [
  'version', 'network', 'fees', 'max_fee_msat', 'max_fee_ppm', 'exempt_fee_msat', 'routing', 'max_cltv_delta', 'amounts',
  'min_channel_reserve_msat', 'max_principal_msat', 'min_principal_msat', 'budget', 'msat', 'period',
  'cooldown_after_failure', 'cooldown_after_success', 'max_in_flight', 'max_snapshot_age', 'proposal_ttl',
  'approval_max_ttl', 'demand', 'mode', 'horizon', 'burst_factor', 'ewma', 'bucket_seconds', 'alpha', 'min_samples',
  'targets', 'min_inbound_msat', 'exclude_channels',
];
// SPEC §10.1 configuration keys; credential and certificate keys are paths (public security model §3.3).
const CONFIG_KEYS = [
  'database', 'policy', 'nodes', 'name', 'implementation', 'url', 'tls_cert_path', 'macaroon_path', 'rune_path',
  'expected_pubkey', 'expected_network', 'key_id', 'escalate_after', 'delta_tolerance_msat', 'alert_dir', 'collect_interval',
];
const RUNBOOKS = ['unknown-recovery', 'stuck-in-flight', 'stuck-lease', 'policy-rollout', 'lab-troubleshooting', 'key-rotation', 'quarantine'];

function markdownFiles(directory: string): string[] {
  const absolute = join(repoRoot, directory);
  if (!existsSync(absolute)) return [];
  return readdirSync(absolute).flatMap(name => {
    const path = join(absolute, name);
    if (statSync(path).isDirectory()) return markdownFiles(relative(repoRoot, path));
    return name.endsWith('.md') ? [relative(repoRoot, path).replace(/\\/g, '/')] : [];
  });
}
function publicDocuments(): string[] {
  return ['README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'NOTICE-SOURCE-REUSE.md', ...markdownFiles('docs')];
}
async function help(): Promise<string> {
  const run = await runCli(['--help']);
  expect(run.status, '--help exits 0').toBe(0);
  return run.stdout;
}
function flagsIn(text: string): Set<string> {
  return new Set(text.match(/(?<![\w-])--[a-z][a-z0-9-]*/g) ?? []);
}
function codeFences(text: string): { lang: string; body: string }[] {
  return [...text.matchAll(/^```([^\n`]*)\r?\n([\s\S]*?)^```/gm)].map(match => ({ lang: (match[1] ?? '').trim(), body: match[2] ?? '' }));
}
/** Command lines written as code: shell fences (and unlabelled ones) and inline code spans. */
function documentedCommandLines(text: string): string[] {
  const fenced = codeFences(text).filter(fence => ['', 'sh', 'bash', 'shell', 'console', 'text', 'powershell'].includes(fence.lang))
    .flatMap(fence => fence.body.split(/\r?\n/)).map(line => line.replace(/^\s*(?:\$|>|PS>)\s*/, '').trim())
    .filter(line => line.startsWith('fluxwarden '));
  const inline = [...text.replace(/^```[\s\S]*?^```/gm, '').matchAll(/`(fluxwarden [^`]+)`/g)].map(match => match[1] ?? '');
  return [...fenced, ...inline];
}
function commandWords(line: string): string[] {
  const words: string[] = [];
  for (const token of line.split(/\s+/).slice(1)) {
    if (/^[-<[|]/.test(token) || token === '') break;
    words.push(token);
  }
  return words;
}
function commandOf(words: readonly string[]): string | null {
  const matches = COMMANDS.filter(command => command.split(' ').every((word, index) => words[index] === word));
  return matches.sort((a, b) => b.length - a.length)[0] ?? null;
}
function exitTable(text: string): [number, string][] {
  return [...text.matchAll(/^\|\s*\**(\d+)\**\s*\|\s*`?([A-Z_]+)`?\s*\|/gm)].map(match => [Number(match[1]), match[2] ?? '']);
}
function yamlBlock(text: string, firstLine: string): string {
  const block = codeFences(text).find(fence => /^ya?ml$/.test(fence.lang) && fence.body.split(/\r?\n/)[0]?.trim().startsWith(firstLine));
  if (block === undefined) throw new Error(`docs/spec.md has no yaml block starting with "${firstLine}"`);
  return block.body;
}
function yamlKeys(text: string): Set<string> {
  return new Set([...text.matchAll(/^\s*(?:-\s+)?([a-z_][a-z0-9_]*):(?:\s|$)/gm)].map(match => match[1] ?? ''));
}

it('CP-042/B1 the command mapping recognises ledger verify and refuses unknown ledger commands', () => {
  // SPEC §9.5 and the ledger command contract require this public verification entry point.
  expect(commandOf(commandWords('fluxwarden ledger verify --json'))).toBe('ledger verify');
  expect(commandOf(commandWords('fluxwarden ledger repair --json'))).toBeNull();
  expect(commandOf(commandWords('fluxwarden unknown verify --json'))).toBeNull();
});

it('CP-042/B1 --help lists every specified command and flag, and each appears in docs/spec.md and README.md', async () => {
  const text = await help();
  const spec = readText('docs/spec.md');
  const readme = readText('README.md');
  for (const command of COMMANDS) {
    expect(text, `--help lists ${command}`).toMatch(new RegExp(`(?:^|\\s)${command.replace(' ', '\\s+')}(?:\\s|$)`, 'm'));
    expect(spec, `docs/spec.md documents fluxwarden ${command}`).toContain(`fluxwarden ${command}`);
    expect(readme, `README.md documents fluxwarden ${command}`).toContain(`fluxwarden ${command}`);
  }
  const helpFlags = flagsIn(text);
  for (const flag of FLAGS) expect(helpFlags.has(flag), `--help lists ${flag}`).toBe(true);
  const specFlags = flagsIn(spec), readmeFlags = flagsIn(readme);
  for (const flag of helpFlags) {
    expect(specFlags.has(flag), `docs/spec.md documents ${flag}`).toBe(true);
    expect(readmeFlags.has(flag), `README.md documents ${flag}`).toBe(true);
  }
});

it('CP-042/B1 every command line written in the documents names a real command and only flags that --help lists', async () => {
  const helpFlags = flagsIn(await help());
  let lines = 0;
  for (const file of publicDocuments()) {
    for (const line of documentedCommandLines(readText(file))) {
      lines += 1;
      const words = commandWords(line);
      if (words.length > 0) expect(commandOf(words), `${file}: "${line}" names a command`).not.toBeNull();
      for (const flag of flagsIn(line)) expect(helpFlags.has(flag), `${file}: "${line}" uses ${flag}`).toBe(true);
    }
  }
  expect(lines, 'the documents show command lines').toBeGreaterThanOrEqual(COMMANDS.length);
});

it('CP-042/B1 every specified command is dispatched by the binary: a missing configuration is refused with exit 2 naming the command', async () => {
  const work = scratchDir('dispatch');
  const config = join(work, 'absent.yaml');
  const argv: Record<string, string[]> = {
    doctor: [], 'nodes list': [], 'nodes inspect': ['node-1'], channels: [], 'liquidity diagnose': [], 'liquidity plan': [],
    'liquidity explain': ['proposal-1'], 'liquidity approve': ['proposal-1', '--key', join(work, 'operator.key')],
    'actions execute': ['proposal-1', '--require-regtest'], 'actions status': ['execution-1'], 'ledger verify': [], reconcile: [],
    'evidence export': ['--run-id', 'run-1', '--out', join(work, 'bundle')], daemon: [],
  };
  for (const [command, rest] of Object.entries(argv)) {
    const run = await runCli([...command.split(' '), ...rest, '--config', config, '--json']);
    expect(run.status, command).toBe(2);
    const document = asRecord(JSON.parse(run.stdout), `${command} document`);
    expect(document['command'], command).toBe(command);
    expect(asRecord(document['error'], `${command} error`)['code'], command).toBe(2);
  }
  // SPEC §10.3 item 13: keys generate needs no configuration; it writes the key and exits 0.
  const key = join(work, 'generated.key');
  const generated = await runCli(['keys', 'generate', '--out', key, '--json']);
  expect(generated.status).toBe(0);
  expect(asRecord(JSON.parse(generated.stdout), 'keys document')['command']).toBe('keys generate');
  expect(existsSync(key)).toBe(true);
});

it('CP-042/B1 exit codes agree across the specification, docs/spec.md, README.md, the code and every labelled mention', () => {
  const expected = Object.entries(EXIT_CODES).map(([code, label]): [number, string] => [Number(code), label]);
  expect(exitTable(readText('docs/spec.md')), 'docs/spec.md exit-code table').toEqual(expected);
  expect(exitTable(readText('README.md')), 'README.md exit-code table').toEqual(expected);
  expect(Object.entries(ExitCode).map(([label, code]) => [code, label]).sort((a, b) => Number(a[0]) - Number(b[0]))).toEqual(expected);
  for (const file of publicDocuments()) {
    const text = readText(file);
    for (const match of text.matchAll(/\bexit(?:s|ed)?(?: code| with)?\s+(\d+)\b(?:\s*\(?`?([A-Z][A-Z_]{3,})`?)?/g)) {
      const code = Number(match[1]);
      expect(code in EXIT_CODES, `${file}: exit ${String(code)} exists`).toBe(true);
      const label = match[2];
      if (label !== undefined && Object.values(EXIT_CODES).includes(label)) expect(label, `${file}: exit ${String(code)} label`).toBe(EXIT_CODES[code]);
    }
  }
});

it('CP-042/B1 the documented configuration and policy contain every specified key and load with the shipped loaders', () => {
  const spec = readText('docs/spec.md');
  const configText = yamlBlock(spec, '# fluxwarden configuration');
  const configKeys = yamlKeys(configText);
  for (const key of CONFIG_KEYS) expect(configKeys.has(key), `documented configuration has ${key}`).toBe(true);
  // SPEC §10.1 names approval_keys; the public security model names approval_public_keys.
  expect(configKeys.has('approval_keys') || configKeys.has('approval_public_keys'), 'documented configuration lists approval keys').toBe(true);
  const work = scratchDir('config');
  const configPath = join(work, 'fluxwarden.yaml');
  writeFileSync(configPath, configText);
  expect(() => loadConfig(configPath), 'documented configuration loads').not.toThrow();
  // Control: the loader refuses a key the documents do not define, so loading proves the documented keys are its keys.
  writeFileSync(configPath, `${configText}\nundocumented_key: 1\n`);
  expect(() => loadConfig(configPath)).toThrow();

  const policyText = yamlBlock(spec, '# fluxwarden policy').replace(/^#\s?(exclude_channels:.*)$/m, '$1').replace(/^#(\s+- .*)$/gm, '$1');
  const policyKeys = yamlKeys(policyText);
  for (const key of POLICY_KEYS) expect(policyKeys.has(key), `documented policy has ${key}`).toBe(true);
  expect(() => loadPolicy(policyText), 'documented policy loads').not.toThrow();
  expect(() => loadPolicy(`${policyText}\nundocumented_key: 1\n`)).toThrow();
});

it('CP-042/B1 every output schema is referenced by the documents, every referenced schema and relative link exists, and README states the package version', () => {
  const documents = publicDocuments();
  const all = documents.map(file => readText(file)).join('\n');
  const schemas = readdirSync(join(repoRoot, 'schemas', 'output')).filter(name => name.endsWith('.json'));
  expect(schemas.length).toBeGreaterThan(0);
  const spec = readText('docs/spec.md');
  for (const schema of schemas) expect(spec, `docs/spec.md references ${schema}`).toContain(`schemas/output/${schema}`);
  for (const match of all.matchAll(/schemas\/output\/([\w.-]+\.json)/g)) expect(schemas, `referenced ${match[1] ?? ''}`).toContain(match[1]);
  for (const file of documents) {
    const text = readText(file).replace(/^```[\s\S]*?^```/gm, '');
    for (const match of text.matchAll(/\]\(([^)\s]+)\)/g)) {
      const target = match[1] ?? '';
      if (/^(?:[a-z]+:|#)/i.test(target)) continue;
      const path = resolve(repoRoot, dirname(file), decodeURIComponent(target.split('#')[0] ?? ''));
      expect(existsSync(path), `${file} links ${target}`).toBe(true);
    }
  }
  const version = String(asRecord(JSON.parse(readText('package.json')), 'package.json')['version']);
  for (const match of readText('README.md').matchAll(/\bversion\s+(\d+\.\d+\.\d+)\b/gi)) expect(match[1], 'README names the current version').toBe(version);
});

it('CP-018/B4 every command line in README passes argument parsing: it differs from the same line with an unknown flag', async () => {
  const lines = documentedCommandLines(readText('README.md')).filter(line => {
    const command = commandOf(commandWords(line));
    return command !== null && !command.startsWith('lab ');
  });
  expect(lines.length, 'README shows runnable commands').toBeGreaterThan(0);
  const work = scratchDir('readme');
  mkdirSync(join(work, 'out'), { recursive: true });
  for (const line of lines) {
    const argv = line.replace(/\s*\[[^\]]*\]/g, '').split(/\s+/).slice(1).filter(token => token !== '--json').map(token => token.replace(/^<[^>]+>$/, 'value-1'))
      .map(token => (/^(?:\.\/)?[\w.-]+\.(?:key|pem|yaml)$/.test(token) ? join(work, 'out', token.replace(/^\.\//, '')) : token));
    const as = await runCli([...argv, '--json']);
    const bogus = await runCli([...argv, '--no-such-flag', '--json']);
    expect(bogus.status, `${line} with an unknown flag`).toBe(2);
    const message = (stdout: string): unknown => asRecord(asRecord(JSON.parse(stdout), 'document')['error'] ?? {}, 'error')['message'];
    if (as.status === 2) expect(message(as.stdout), `"${line}" is refused only after argument parsing`).not.toBe(message(bogus.stdout));
    expect(asRecord(JSON.parse(as.stdout), 'document')['command'], line).toBe(commandOf(commandWords(line)));
  }
});

function section(text: string): string {
  return text.replace(/\s+/g, ' ');
}

it('CP-042/B2 the runbooks exist, are indexed and state the specified recovery behaviour', () => {
  const index = readText('docs/runbooks/README.md');
  const read = (name: string): string => {
    const path = `docs/runbooks/${name}.md`;
    expect(existsSync(join(repoRoot, path)), path).toBe(true);
    expect(index, `index links ${name}.md`).toMatch(new RegExp(`\\]\\((?:\\./)?${name}\\.md\\)`));
    return section(readText(path));
  };
  for (const name of RUNBOOKS) expect(read(name).length, `${name} has content`).toBeGreaterThan(200);
  const exits = (text: string, code: number): boolean => new RegExp(`\\bexit(?:s| code| with)?\\s+${String(code)}\\b`, 'i').test(text);

  // SPEC §8.4, §8.5, §10.3 AE11: resolve by payment hash through reconcile; never retry.
  const unknown = read('unknown-recovery');
  for (const term of ['fluxwarden reconcile', 'UNKNOWN', 'NOT_FOUND', 'VERIFIED_SUCCESS', 'VERIFIED_FAILURE']) expect(unknown, `unknown-recovery: ${term}`).toContain(term);
  expect(unknown).toMatch(/payment[ _]hash/i);
  expect(unknown).toMatch(/\b(?:do not|never|must not)\s+retry\b/i);
  expect(exits(unknown, 7), 'unknown-recovery: exit 7').toBe(true);

  // SPEC §8.6: escalate_after, alert stuck-in-flight, reservation stays HELD, never resolved by assumption.
  const stuck = read('stuck-in-flight');
  for (const term of ['escalate_after', 'stuck-in-flight', 'HELD', 'fluxwarden reconcile', 'IN_FLIGHT']) expect(stuck, `stuck-in-flight: ${term}`).toContain(term);
  expect(stuck).toMatch(/assum/i);
  expect(exits(stuck, 7), 'stuck-in-flight: exit 7').toBe(true);

  // SPEC §6.5, §10.3 AE4/AE9: expired leases before sending are re-claimed or cancelled; after sending, never re-sent.
  const lease = read('stuck-lease');
  for (const term of ['CLAIMED', 'PREFLIGHT', 'CANCELLED', 'SUBMITTING', 'fence_epoch', 'lease-lost', 'claimed-elsewhere']) expect(lease, `stuck-lease: ${term}`).toContain(term);
  expect(lease).toMatch(/(?:never|not)\s+(?:be\s+)?re-?(?:sent|claimed)/i);

  // SPEC §7.1, §7.6, §10.3 LP1/LA3: a new policy digest invalidates approvals; re-plan and re-approve.
  const rollout = read('policy-rollout');
  for (const term of ['policy_sha256', 'policy_versions', 'fluxwarden liquidity plan', 'fluxwarden liquidity approve', 'max_snapshot_age']) expect(rollout, `policy-rollout: ${term}`).toContain(term);
  expect(exits(rollout, 1), 'policy-rollout: exit 1').toBe(true);

  // SPEC §10.3 item 12, §11.3.
  const lab = read('lab-troubleshooting');
  for (const term of ['fluxwarden lab up', 'fluxwarden lab down', 'labs/.runtime/lab.json', 'regtest']) expect(lab, `lab-troubleshooting: ${term}`).toContain(term);
  for (const code of [2, 4, 5]) expect(exits(lab, code), `lab-troubleshooting: exit ${String(code)}`).toBe(true);

  // SPEC §7.7, §10.3 items 7, 8, 13: operator key generation, public keys by key_id, unknown key_id exit 2.
  const keys = read('key-rotation');
  for (const term of ['fluxwarden keys generate', 'key_id', '0600']) expect(keys, `key-rotation: ${term}`).toContain(term);
  expect(keys).toMatch(/approval_(?:public_)?keys/);
  expect(exits(keys, 2), 'key-rotation: exit 2 for an unknown key_id').toBe(true);
  expect(exits(keys, 5), 'key-rotation: exit 5 when no stored approval verifies').toBe(true);

  // SPEC §5.2 H3, §10.4 DM2/DM5, INV-12. The specification defines no command that lifts a quarantine;
  // the runbook says so and names none.
  const quarantine = read('quarantine');
  for (const term of ['QUARANTINED', 'expected_pubkey', 'expected_network', 'node-quarantined', 'identity']) expect(quarantine, `quarantine: ${term}`).toContain(term);
  expect(exits(quarantine, 5), 'quarantine: exit 5').toBe(true);
  expect(quarantine).toMatch(/daemon[^.]*\babort/i);
  expect(quarantine).toMatch(/\bno\b[^.]*\bcommand\b[^.]*quarantin|quarantin[^.]*\bno\b[^.]*\bcommand\b/i);
  expect(quarantine).not.toMatch(/\bUPDATE\s+nodes\b|\bunquarantine\b/i);
});

// Positioning claims (public positioning rule). Prose documents take the strict phrase list; the
// specification documents, which use "first" and "only" technically, take the claim list.
const STRICT = [/\bthe\s+first\b/i, /\bthe\s+only\b/i, /\bfirst-of-its-kind\b/i, /\bunique\b/i];
const CLAIMS = [/\b(?:the\s+)?(?:first|only)\s+(?:open[- ]source\s+)?(?:tool|controller|project|product|solution|software)\b/i, /\bfirst-of-its-kind\b/i, /\bunique(?:ly)?\s+(?:tool|controller|approach|solution|product|project)\b/i];
// Generic development vocabulary that does not belong in shipped documents.
const VOCABULARY = [
  /\bCP-\d{3}\b/, /\bDecision\s+D\d+\b/, /\(D\d+(?:[,;/ ]+D?\d+)*\)/, /\bresearch\s+\d{1,2}\b/i,
  /\bTODO\b/, /\bTBD\b/, /\bFIXME\b/, /\bUNRESOLVED\b/, /^\s*placeholder\b/im, /\bplaceholder (?:for|until)\b/i, /\bWIP\b/,
  new RegExp(['\\bco', 'authored', 'by\\b'].join('-'), 'i'), new RegExp(['\\bgenerated', 'with\\b'].join(' '), 'i'),
  /\bM\d-(?:REL|\d+)\b/, /\(A\d{1,2}(?:[,;/ ]+A?\d{1,2})*\)/,
];

it('CP-042/B3 forbidden positioning words and development vocabulary are absent from the documents, schemas and --help', async () => {
  for (const sample of ['the first controller', 'THE ONLY tool', 'a unique design']) expect(STRICT.some(pattern => pattern.test(sample)), sample).toBe(true);
  for (const sample of ['per research 05', 'TODO: fill in', 'Placeholder for runbooks']) expect(VOCABULARY.some(pattern => pattern.test(sample)), sample).toBe(true);
  for (const sample of [['Co', 'Authored', 'By'].join('-'), ['Generated', 'with'].join(' ')]) expect(VOCABULARY.some(pattern => pattern.test(sample)), sample).toBe(true);
  for (const sample of ['the first SIGINT asks the command to stop', 'UNIQUE(nonce)', 'version 3']) expect(VOCABULARY.some(pattern => pattern.test(sample)), sample).toBe(false);
  const specification = new Set(['docs/spec.md', 'docs/architecture.md', 'docs/security-model.md', 'docs/references.md', 'docs/references/failure-catalogue.md']);
  const texts: [string, string][] = [
    ...publicDocuments().map((file): [string, string] => [file, readText(file)]),
    ...readdirSync(join(repoRoot, 'schemas', 'output')).map((name): [string, string] => [`schemas/output/${name}`, readText(`schemas/output/${name}`)]),
    ['--help', await help()],
  ];
  for (const [file, text] of texts) {
    const normalized = text.normalize('NFKC').replace(/[*_`]/g, '');
    const positioning = specification.has(file) || file.startsWith('schemas/') || file === '--help' ? CLAIMS : STRICT;
    for (const pattern of positioning) expect(pattern.exec(normalized)?.[0], `${file}: ${String(pattern)}`).toBeUndefined();
    for (const pattern of VOCABULARY) expect(pattern.exec(text)?.[0], `${file}: ${String(pattern)}`).toBeUndefined();
  }
});

it('CP-042/B4 the failure catalogue has a maintenance section and every catalogue id cited by a test exists in it', () => {
  const catalogue = readText('docs/references/failure-catalogue.md');
  expect(catalogue).toMatch(/^#{2,}\s+.*\bmaintenance\b/im);
  const listed = new Set(catalogue.match(/\bFC-[A-Za-z]+-\d+\b/g) ?? []);
  const testFiles = (directory: string): string[] => readdirSync(directory).flatMap(name => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? testFiles(path) : /\.(?:ts|mjs|json)$/.test(name) ? [path] : [];
  });
  for (const file of testFiles(join(repoRoot, 'test'))) {
    for (const id of readText(relative(repoRoot, file)).match(/\bFC-[A-Za-z]+-\d+\b/g) ?? []) {
      expect(listed.has(id), `${relative(repoRoot, file)} cites ${id}`).toBe(true);
    }
  }
});

it('CP-042/B5 no public document cites a private research note, and every reference entry carries its source link', () => {
  for (const file of publicDocuments()) expect(/\bresearch\s+(?:notes?\s+)?\d{1,2}\b/i.exec(readText(file))?.[0], file).toBeUndefined();
  const references = readText('docs/references.md').replace(/^## Positioning\s*\r?\n[\s\S]*?(?=^## |(?![\s\S]))/m, '');
  const entries = references.split(/\r?\n/).filter(line => /^\s*(?:[-*]|\d+\.)\s+\S/.test(line));
  expect(entries.length, 'references list entries').toBeGreaterThan(0);
  for (const entry of entries) expect(entry, 'entry has a source').toMatch(/https:\/\/\S+/);
});
