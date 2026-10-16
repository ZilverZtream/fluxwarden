// SECURITY INV-11 / SPEC EV2: exports contain no known configured credential,
// including a credential repeated in ordinary persisted version metadata.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import type { FakeServer } from '../fakes/https.js';
import { loadSource } from '../helpers/adapter-interfaces.js';
import { demo, documentOf, resultOf } from '../helpers/cpw-cli.js';
import { declareDeliberateOutputs } from '../helpers/output.js';

const open: FakeServer[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(server => server.close())); });

interface SecretChecker { foundIn: (bytes: Uint8Array) => boolean }

for (const metadata of ['clean', 'known-configured-rune'] as const) {
  it(`CP-039/REG-CLI009 evidence export protects ${metadata} persisted metadata`, async () => {
    const d = await demo(open, { withKey: false });
    const { Secret } = await loadSource<{ Secret: new (bytes: Uint8Array) => SecretChecker }>('core/secret.ts');
    const known = new Secret(Buffer.from(d.cln.rune));
    // The rune belongs to the configured disposable fake node. A normal CLI
    // run admits it through that node's configured credential file.
    declareDeliberateOutputs([d.database, `${d.database}-wal`, `${d.database}-shm`]);
    const reconciled = await d.run(['--json', 'reconcile', '--node', 'cln-m', '--since', '1h']);
    expect(reconciled.status, 'ordinary empty-ledger reconciliation succeeds').toBe(0);
    const runId = String(resultOf(documentOf(reconciled, 'reconcile'))['run_id']);
    const runFile = `${d.database}.${runId}.json`;
    declareDeliberateOutputs([runFile]);
    // Persisted EvidenceInput uses the same public manifest contract as the
    // evidence bundle interface. Only ordinary metadata is changed here.
    const input = JSON.parse(readFileSync(runFile, 'utf8')) as { manifest: { nodes: { version: string }[] } };
    const node = input.manifest.nodes[0];
    if (node === undefined) throw new Error('the ordinary CLI run must record its node manifest');
    node.version += metadata === 'clean' ? ' ordinary-metadata' : ` ${d.cln.rune}`;
    writeFileSync(runFile, JSON.stringify(input));
    const outDir = join(d.dir, 'exported-evidence');
    declareDeliberateOutputs([
      'manifest.json', 'reconciliation.json', 'topology-before.json', 'topology-after.json', 'proposals.json',
      'execution-trace.ndjson', 'ledger-audit.json', 'chaos-results.json', 'checksums.sha256',
    ].map(file => join(outDir, file)));
    const exported = await d.run(['--json', 'evidence', 'export', '--run-id', runId, '--out', outDir]);
    if (metadata === 'known-configured-rune' && exported.status === 8) {
      expect(existsSync(outDir)).toBe(false);
    } else {
      expect(exported.status).toBe(0);
      const files = readdirSync(outDir);
      expect(files).toHaveLength(9);
      expect(files.some(file => known.foundIn(readFileSync(join(outDir, file)))),
        'completed bundle contains no configured credential in any supported representation').toBe(false);
      if (metadata === 'clean') expect(files.some(file => readFileSync(join(outDir, file)).includes('ordinary-metadata')),
        'ordinary persisted version metadata is preserved').toBe(true);
    }
    expect(known.foundIn(Buffer.from(exported.stdout + exported.stderr)), 'export diagnostics omit the configured credential').toBe(false);
  });
}
