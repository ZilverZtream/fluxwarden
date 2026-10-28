// Public workflow semantics: retain unconditional full captured-evidence scan,
// full verification before sealing, and independently safe bounded uploads.
// D29 permits the always-run seal to own its full verification exactly once.
import { expect } from 'vitest';
import { asRecord } from './cli.js';

export function proveChaosUpload(workflow: Record<string, unknown>, chaos: Record<string, unknown>): void {
  const permissions = asRecord(chaos['permissions'] ?? workflow['permissions'], 'effective permissions');
  expect(permissions['contents']).toBe('read'); expect(permissions['actions']).toBe('read');
  for (const [key, value] of Object.entries(permissions)) { expect(['contents', 'actions']).toContain(key); expect(value).toBe('read'); }
  expect(JSON.stringify(chaos)).not.toMatch(/secrets\./);
  expect(String(chaos['if'])).toMatch(/github\.event_name\s*==\s*'workflow_dispatch'/);
  if (!Array.isArray(chaos['steps'])) throw new Error('chaos workflow steps required');
  const steps = chaos['steps'].map(value => asRecord(value, 'step'));
  const run = steps.findIndex(step => /\bnpm run test:chaos\b/.test(String(step['run'] ?? '')));
  expect(run).toBeGreaterThanOrEqual(0);
  const command = String(steps[run]?.['run']);
  expect(command).toMatch(/scripts\/ci-capture\.mjs\b.*\s--\s+node scripts\/ci-job\.mjs\b/);
  expect(command).toMatch(/--next node scripts\/no-pending\.mjs\s+"?\$FLUXWARDEN_EVIDENCE_DIR\/vitest-chaos\.json"?/);
  const final = command.indexOf('--finally node scripts/leak-check.mjs');
  expect(final, 'original full scanner remains an unconditional failure finalizer').toBeGreaterThan(command.indexOf('npm run test:chaos'));
  expect(command.slice(final)).toMatch(/^--finally node scripts\/leak-check\.mjs --sentinels test\/sentinels\.json --sentinel-dir "\$FLUXWARDEN_SENTINEL_DIR" "\$FLUXWARDEN_EVIDENCE_DIR"$/);
  const verify = steps.findIndex(step => step['id'] === 'capture-verify');
  const seal = steps.findIndex(step => step['id'] === 'report-seal');
  expect(seal, 'actual proof producer follows the captured workload').toBeGreaterThan(run);
  expect(String(steps[seal]?.['run']).trim(), 'only the exact live/chaos proof producer earns verification credit').toMatch(/^node scripts\/release-ci\.mjs seal --key (?:live\/chaos|"live\/chaos"|'live\/chaos')$/);
  const condition = (value: unknown): string => String(value).replace(/\s+/g, '');
  const requireCondition = (step: Record<string, unknown> | undefined, terms: string[]): void => {
    expect(condition(step?.['if']).split('&&').sort(), 'every required success guard remains conjunctive').toEqual([...terms].sort());
    expect(step?.['continue-on-error'] ?? false).toBe(false);
  };
  if (verify >= 0) {
    expect(verify).toBeGreaterThan(run); expect(seal).toBeGreaterThan(verify);
    expect(steps[verify]?.['run']).toBe('node scripts/ci-capture.mjs verify --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR"');
    requireCondition(steps[verify], ['always()']);
    requireCondition(steps[seal], ['always()', "steps.capture-verify.outcome=='success'"]);
  } else {
    // The real sealing entry point performs full original verification before
    // any output. Its unconditional invocation owns the existing single epoch.
    requireCondition(steps[seal], ['always()']);
  }
  const uploads = steps.map((step, index) => ({ step, index })).filter(({ step }) => String(step['uses'] ?? '').startsWith('actions/upload-artifact@'));
  const named = (name: string) => uploads.filter(({ step }) => asRecord(step['with'], 'upload')['name'] === name);
  const receipt = named('chaos-capture'), bounded = named('fluxwarden-live-chaos');
  expect(receipt).toHaveLength(1); expect(bounded).toHaveLength(1); expect(uploads).toHaveLength(2);
  const normalize = (value: unknown): string => String(value).trim().replace(/\$\{\{\s*env\.(FLUXWARDEN_[A-Z_]+)\s*\}\}/g, (_match, name: string) => `$${name}`);
  for (const { step, index } of uploads) {
    expect(String(step['uses'])).toMatch(/^actions\/upload-artifact@[0-9a-f]{40}$/);
    const options = asRecord(step['with'], 'upload options'), path = normalize(options['path']);
    expect(path).not.toMatch(/\.runtime|labs\/?$|\bsentinels?\b/);
    expect(options['if-no-files-found']).toBe('error');
    if (options['name'] === 'chaos-capture') {
      expect(path).toBe('$FLUXWARDEN_CI_CAPTURE_DIR/receipt.json');
      if (verify >= 0 && condition(step['if']) === "always()&&steps.capture-verify.outcome=='success'") {
        expect(index).toBeGreaterThan(verify);
        requireCondition(step, ['always()', "steps.capture-verify.outcome=='success'"]);
      } else {
        // D29 diagnostic confidentiality alone never authorizes release output.
        const metadata = steps.findIndex(value => value['id'] === 'capture-metadata');
        expect(metadata).toBeGreaterThan(run); expect(index).toBeGreaterThan(metadata);
        expect(steps[metadata]?.['run']).toBe('node scripts/ci-safe-capture-metadata.mjs --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR"');
        requireCondition(steps[metadata], ['always()']);
        requireCondition(step, ['always()', "steps.capture-metadata.outcome=='success'", "steps.capture-metadata.outputs.available=='true'"]);
      }
    } else {
      expect(index).toBeGreaterThan(seal);
      expect(path, 'only final scanned bounded JSON is uploaded').toBe('$FLUXWARDEN_RELEASE_OUTPUT/*.json');
      requireCondition(step, verify >= 0 ? ['always()', "steps.capture-verify.outcome=='success'", "steps.report-seal.outcome=='success'"]
        : ['always()', "steps.report-seal.outcome=='success'"]);
    }
  }
}