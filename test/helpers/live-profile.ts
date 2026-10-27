import { readFileSync } from 'node:fs';
import { assertPlannerCapture } from '../../labs/scenarios/live-profile.mjs';

/** Per-file startup must produce the observations consumed by CP014/015. */
export function currentPlannerCapture(): string {
  const captureDir = process.env['FLUXWARDEN_LAB_CAPTURE_DIR'], ownerPath = process.env['FLUXWARDEN_LAB_OWNER'], planPath = process.env['FLUXWARDEN_LAB_PLAN'];
  if (!captureDir || !ownerPath || !planPath) throw new Error('LabInvalidError: current owned native captures required');
  const plan = JSON.parse(readFileSync(planPath, 'utf8')) as Record<string, unknown>;
  assertPlannerCapture(captureDir, ownerPath, String(plan['sourceCommit']));
  return captureDir;
}
