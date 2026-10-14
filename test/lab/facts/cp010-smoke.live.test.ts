// Smoke payments across implementations (SPEC 11.2 topology): LND-P -> LND-R -> CLN-M and
// CLN-P -> CLN-R -> LND-R, each settled and visible on both sides with the node's own tools.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { repoRoot } from '../../helpers/cli.js';
import { clnInvoice, lab, list, lndInvoice, newPreimage, text, LabInvalidError } from '../../helpers/lab.js';

interface Scanner { findLeaks(options: { root: string; sentinels: string; sentinelDir: string; testTmp: string; evidenceDir: string; paths: string[] }): { path: string; encoding: string } | null }

describe('smoke payments', () => {
  it('CP-010/R1 LND-P pays a CLN-M invoice and both nodes report it settled for the exact amount', async () => {
    const l = lab();
    const { preimage, hash } = newPreimage();
    const invoice = await clnInvoice(l, 30_000_000n, `smoke-${hash.slice(0, 12)}`, 'smoke', preimage);
    const paid = l.ok('lnd-p', ['payinvoice', '--force', '--json', text(invoice['bolt11'], 'bolt11')]);
    expect([paid['status'], paid['payment_hash'], paid['value_msat'], paid['payment_preimage']]).toEqual(['SUCCEEDED', hash, '30000000', preimage]);
    const listed = list(l.ok('lnd-p', ['listpayments', '--max_payments', '1000'])['payments'], 'payments').filter(row => row['payment_hash'] === hash);
    expect(listed.map(row => [row['status'], row['value_msat']])).toEqual([['SUCCEEDED', '30000000']]);
    const received = list(l.ok('cln-m', ['listinvoices', `payment_hash=${hash}`])['invoices'], 'invoices');
    expect(received.map(row => [row['status'], row['amount_received_msat'], row['payment_preimage']])).toEqual([['paid', 30_000_000, preimage]]);
  }, 180_000);

  it('CP-010/R2 CLN-P pays an LND-R invoice and both nodes report it settled for the exact amount', async () => {
    const l = lab();
    const { preimage, hash } = newPreimage();
    const invoice = await lndInvoice(l, 'lnd-r', 30_000_000n, preimage);
    const paid = l.ok('cln-p', ['xpay', `invstring=${text(invoice['payment_request'], 'bolt11')}`]);
    expect([paid['amount_msat'], paid['payment_preimage']]).toEqual([30_000_000, preimage]);
    const sent = list(l.ok('cln-p', ['listpays', `payment_hash=${hash}`])['pays'], 'pays');
    expect(sent.map(row => row['status'])).toEqual(['complete']);
    const settled = l.ok('lnd-r', ['lookupinvoice', hash]);
    expect([settled['state'], settled['amt_paid_msat']]).toEqual(['SETTLED', '30000000']);
  }, 180_000);

  // INV-11: preimages the suite created are absent, in every encoding, from its transcript and scratch.
  it('CP-010/Rleak the facts transcript and scratch contain no registered preimage in any encoding', async () => {
    const tmp = process.env['FLUXWARDEN_TEST_TMP'], sentinelDir = process.env['FLUXWARDEN_SENTINEL_DIR'], evidenceDir = process.env['FLUXWARDEN_EVIDENCE_DIR'];
    if (!tmp || !sentinelDir || !evidenceDir) throw new LabInvalidError('explicit private temporary, sentinel and evidence roots are required');
    newPreimage();
    const registered = readdirSync(sentinelDir).filter(name => name.startsWith('lab-preimage-'));
    expect(registered.length).toBeGreaterThan(0);
    const transcript = join(evidenceDir, 'lab-facts-transcript.jsonl');
    if (!existsSync(transcript)) throw new LabInvalidError('the facts suite wrote no transcript in this run');
    const scanner = await import(pathToFileURL(join(repoRoot, 'scripts/leak-check.mjs')).href) as Scanner;
    expect(scanner.findLeaks({ root: repoRoot, sentinels: join(repoRoot, 'test/sentinels.json'), sentinelDir, testTmp: tmp, evidenceDir, paths: [transcript, tmp] })).toBeNull();
    // Control: the same scan does report a registered preimage planted in hex.
    const control = mkdtempSync(join(tmp, 'cp010-leak-')), planted = join(control, 'planted.txt');
    writeFileSync(planted, readFileSync(join(sentinelDir, registered[0] ?? '')).toString('hex'));
    try { expect(scanner.findLeaks({ root: repoRoot, sentinels: join(repoRoot, 'test/sentinels.json'), sentinelDir, testTmp: tmp, evidenceDir, paths: [planted] })).not.toBeNull(); }
    finally { rmSync(control, { recursive: true, force: true }); }
  }, 180_000);
});
