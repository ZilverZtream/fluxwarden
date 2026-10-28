// D29 combined-verification and diagnostic-confidentiality workflow controls.
// These synthetic workflows are observable interface fixtures, never CI proof.
import { expect, it } from 'vitest';
import { proveChaosUpload } from '../helpers/oct26-chaos-upload.js';

type Step = Record<string, unknown>;
function fixture(combined: boolean): { workflow: Record<string, unknown>; chaos: Record<string, unknown>; steps: Step[] } {
  const run: Step = { run: 'node scripts/ci-capture.mjs --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR" -- node scripts/ci-job.mjs --commands-only -- npm run test:chaos -- --reporter=json --outputFile="$FLUXWARDEN_EVIDENCE_DIR/vitest-chaos.json" --next node scripts/no-pending.mjs "$FLUXWARDEN_EVIDENCE_DIR/vitest-chaos.json" --finally node scripts/leak-check.mjs --sentinels test/sentinels.json --sentinel-dir "$FLUXWARDEN_SENTINEL_DIR" "$FLUXWARDEN_EVIDENCE_DIR"' };
  const verify: Step = { id: 'capture-verify', if: 'always()', run: 'node scripts/ci-capture.mjs verify --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR"' };
  const seal: Step = { id: 'report-seal', if: combined ? 'always()' : "always() && steps.capture-verify.outcome == 'success'", run: 'node scripts/release-ci.mjs seal --key "live/chaos"' };
  const metadata: Step = { id: 'capture-metadata', if: 'always()', run: 'node scripts/ci-safe-capture-metadata.mjs --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR"' };
  const receipt: Step = { uses: `actions/upload-artifact@${'a'.repeat(40)}`, if: combined ? "always() && steps.capture-metadata.outcome == 'success' && steps.capture-metadata.outputs.available == 'true'" : "always() && steps.capture-verify.outcome == 'success'",
    with: { name: 'chaos-capture', path: '${{ env.FLUXWARDEN_CI_CAPTURE_DIR }}/receipt.json', 'if-no-files-found': 'error' } };
  const report: Step = { uses: `actions/upload-artifact@${'a'.repeat(40)}`, if: combined ? "always() && steps.report-seal.outcome == 'success'" : "always() && steps.capture-verify.outcome == 'success' && steps.report-seal.outcome == 'success'",
    with: { name: 'fluxwarden-live-chaos', path: '${{ env.FLUXWARDEN_RELEASE_OUTPUT }}/*.json', 'if-no-files-found': 'error' } };
  const steps = [run, ...(combined ? [] : [verify]), seal, ...(combined ? [metadata] : []), receipt, report];
  return { workflow: { permissions: { contents: 'read', actions: 'read' } }, chaos: { if: "github.event_name == 'workflow_dispatch'", steps }, steps };
}
function step(f: ReturnType<typeof fixture>, id: string): Step {
  const found = f.steps.find(value => value['id'] === id || (value['with'] as Record<string, unknown> | undefined)?.['name'] === id);
  if (!found) throw new Error('required synthetic workflow control absent'); return found;
}

it('CP-044/CHAOS-UPLOAD full standalone verification and always-run combined sealing both preserve exact guarded upload controls', () => {
  for (const combined of [false, true]) { const f = fixture(combined); proveChaosUpload(f.workflow, f.chaos); }
});

it('CP-044/CHAOS-UPLOAD malformed stale wrong-key disabled reordered OR and diagnostic-only uploads cannot earn proof credit', () => {
  const mutations: ((f: ReturnType<typeof fixture>) => void)[] = [
    f => { f.steps.splice(f.steps.findIndex(value => value['id'] === 'report-seal'), 1); },
    f => { step(f, 'report-seal')['run'] = 'echo node scripts/release-ci.mjs seal --key live/chaos'; },
    f => { step(f, 'report-seal')['run'] = 'node scripts/release-ci.mjs seal --key live/lab'; },
    f => { step(f, 'report-seal')['run'] = 'node scripts/release-ci.mjs seal --key live/chaos || true'; },
    f => { step(f, 'report-seal')['if'] = 'success()'; },
    f => { step(f, 'report-seal')['if'] = 'always() && false'; },
    f => { step(f, 'report-seal')['continue-on-error'] = true; },
    f => { step(f, 'report-seal')['id'] = 'stale-report-seal'; },
    f => { const seal = step(f, 'report-seal'); f.steps.splice(f.steps.indexOf(seal), 1); f.steps.unshift(seal); },
    f => { const upload = step(f, 'fluxwarden-live-chaos'); f.steps.splice(f.steps.indexOf(upload), 1); f.steps.unshift(upload); },
    f => { step(f, 'fluxwarden-live-chaos')['if'] = "always() || steps.report-seal.outcome == 'success'"; },
    f => { step(f, 'fluxwarden-live-chaos')['if'] = "always() && steps.capture-metadata.outcome == 'success' && steps.capture-metadata.outputs.available == 'true'"; },
    f => { step(f, 'fluxwarden-live-chaos')['if'] = "always() && steps.capture-verify.outcome == 'success'"; },
    f => { step(f, 'chaos-capture')['if'] = 'always()'; },
    f => { step(f, 'chaos-capture')['with'] = { name: 'chaos-capture', path: '${{ env.FLUXWARDEN_CI_CAPTURE_DIR }}/*.json', 'if-no-files-found': 'error' }; },
    f => { step(f, 'fluxwarden-live-chaos')['with'] = { name: 'fluxwarden-live-chaos', path: '${{ env.FLUXWARDEN_EVIDENCE_DIR }}/*.json', 'if-no-files-found': 'error' }; },
    f => { f.steps.push({ ...step(f, 'fluxwarden-live-chaos'), with: { name: 'extra-artifact', path: '${{ env.FLUXWARDEN_RELEASE_OUTPUT }}/*.json', 'if-no-files-found': 'error' } }); },
    f => { const run = f.steps[0]; if (!run) throw new Error('run absent'); run['run'] = String(run['run']).replace('--finally node scripts/leak-check.mjs', '--next node scripts/leak-check.mjs'); },
    f => { const run = f.steps[0]; if (!run) throw new Error('run absent'); run['run'] = String(run['run']).replace('scripts/no-pending.mjs', 'scripts/unrelated.mjs'); },
  ];
  for (const combined of [false, true]) for (const mutate of mutations) {
    const f = fixture(combined); mutate(f); expect(() => { proveChaosUpload(f.workflow, f.chaos); }).toThrow();
  }
  for (const mutate of [
    (f: ReturnType<typeof fixture>) => { step(f, 'capture-metadata')['run'] = 'echo node scripts/ci-safe-capture-metadata.mjs --root "$PWD" --capture-dir "$FLUXWARDEN_CI_CAPTURE_DIR"'; },
    (f: ReturnType<typeof fixture>) => { step(f, 'capture-metadata')['if'] = 'success()'; },
    (f: ReturnType<typeof fixture>) => { step(f, 'capture-metadata')['continue-on-error'] = true; },
    (f: ReturnType<typeof fixture>) => { step(f, 'chaos-capture')['if'] = "always() && steps.capture-metadata.outcome == 'success'"; },
    (f: ReturnType<typeof fixture>) => { step(f, 'chaos-capture')['if'] = "always() || steps.capture-metadata.outcome == 'success' && steps.capture-metadata.outputs.available == 'true'"; },
    (f: ReturnType<typeof fixture>) => { const upload = step(f, 'chaos-capture'); f.steps.splice(f.steps.indexOf(upload), 1); f.steps.unshift(upload); },
  ]) { const f = fixture(true); mutate(f); expect(() => { proveChaosUpload(f.workflow, f.chaos); }).toThrow(); }
});
