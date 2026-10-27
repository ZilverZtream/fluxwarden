// Public workflow semantics: retain unconditional full captured-evidence scan,
// then independently verify capture and seal/scan bounded JSON before upload.
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
  const verify = steps.findIndex(step => String(step['run'] ?? '').trim() === 'node scripts/ci-capture.mjs verify --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR"');
  expect(verify).toBeGreaterThan(run); expect(steps[verify]?.['if']).toBe('always()');
  expect(steps[verify]?.['id']).toBe('capture-verify');
  const seal = steps.findIndex(step => /\bnode scripts\/release-ci\.mjs seal --key ["']?live\/chaos["']?(?:\s|$)/.test(String(step['run'] ?? '')));
  expect(seal, 'actual proof producer follows independent capture verification').toBeGreaterThan(verify);
  expect(steps[seal]?.['id']).toBe('report-seal');
  expect(String(steps[seal]?.['if']).replace(/\s+/g, ''), 'unsafe/unverified capture cannot be sealed').toBe("always()&&steps.capture-verify.outcome=='success'");
  const uploads = steps.map((step, index) => ({ step, index })).filter(({ step }) => String(step['uses'] ?? '').startsWith('actions/upload-artifact@'));
  const named = (name: string) => uploads.filter(({ step }) => asRecord(step['with'], 'upload')['name'] === name);
  const receipt = named('chaos-capture'), bounded = named('fluxwarden-live-chaos');
  expect(receipt).toHaveLength(1); expect(bounded).toHaveLength(1);
  const normalize = (value: unknown): string => String(value).trim().replace(/\$\{\{\s*env\.(FLUXWARDEN_[A-Z_]+)\s*\}\}/g, (_match, name: string) => `$${name}`);
  for (const { step, index } of uploads) {
    expect(String(step['uses'])).toMatch(/^actions\/upload-artifact@[0-9a-f]{40}$/);
    const options = asRecord(step['with'], 'upload options'), path = normalize(options['path']);
    expect(path).not.toMatch(/\.runtime|labs\/?$|\bsentinels?\b/);
    expect(options['if-no-files-found']).toBe('error');
    if (options['name'] === 'chaos-capture') {
      expect(index).toBeGreaterThan(verify); expect(path).toBe('$FLUXWARDEN_CI_CAPTURE_DIR/receipt.json');
      expect(String(step['if']).replace(/\s+/g, '')).toBe("always()&&steps.capture-verify.outcome=='success'");
    } else {
      expect(index).toBeGreaterThan(seal);
      expect(path, 'only final scanned bounded JSON is uploaded').toBe('$FLUXWARDEN_RELEASE_OUTPUT/*.json');
      expect(String(step['if']).replace(/\s+/g, '').split('&&').sort()).toEqual([
        'always()', "steps.capture-verify.outcome=='success'", "steps.report-seal.outcome=='success'",
      ].sort());
    }
  }
}
