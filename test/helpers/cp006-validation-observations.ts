import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { reportedCaseName } from '../../labs/scenarios/live-profile.mjs';

export class LabInvalidError extends Error {
  constructor(reason: string) { super(reason); this.name = 'LabInvalidError'; }
}

type RecordValue = Record<string, unknown>;
const stages = ['build', 'setup', 'run', 'teardown', 'leak'] as const;
type Stage = typeof stages[number];
interface Interval { startedAt: number; finishedAt: number }
interface Command extends Interval { phase: Stage; report?: string }
function requireObservation(condition: unknown, reason: string): asserts condition {
  if (!condition) throw new LabInvalidError(reason);
}
function record(value: unknown): RecordValue {
  requireObservation(value !== null && typeof value === 'object' && !Array.isArray(value), 'observation must be an object');
  return value as RecordValue;
}
function list(value: unknown): unknown[] {
  requireObservation(Array.isArray(value), 'observation must be a list'); return value;
}
function text(value: unknown): string {
  requireObservation(typeof value === 'string' && value.length > 0, 'nonempty safe observation text required');
  for (let index = 0; index < value.length; ++index) requireObservation(value.charCodeAt(index) >= 32, 'observation text contains a control character');
  return value;
}
function number(value: unknown): number {
  requireObservation(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0, 'measured nonnegative integer required'); return value;
}
function reporterMilliseconds(value: unknown): number {
  requireObservation(typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER, 'finite nonnegative original reporter milliseconds required'); return value;
}
function interval(value: unknown): Interval {
  const raw = record(value), startedAt = number(raw['startedAt']), finishedAt = number(raw['finishedAt']);
  requireObservation(finishedAt >= startedAt, 'observation ends before it starts'); return { startedAt, finishedAt };
}
function inside(root: string, file: string): boolean {
  const selected = relative(root, file); return selected !== '' && selected !== '..' && !selected.startsWith(`..${sep}`) && !isAbsolute(selected);
}
function ownedFile(root: string, input: unknown): string {
  const file = text(input);
  requireObservation(!isAbsolute(file), 'observation artifact paths must be relative to the declared root');
  const full = resolve(root, file);
  requireObservation(inside(root, full), 'observation path escapes the declared root');
  const actual = realpathSync(full);
  requireObservation(inside(root, actual) && actual === full && !lstatSync(full).isSymbolicLink() && lstatSync(full).isFile(), 'observation must be an ordinary file inside its declared root');
  requireObservation(lstatSync(full).size <= 16 * 1024 * 1024, 'observation artifact exceeds bounded input size');
  return full;
}
function readJson(file: string): unknown { return JSON.parse(readFileSync(file, 'utf8')) as unknown; }
function sourceIdentity(value: unknown): string {
  const digest = text(value); requireObservation(/^[a-f0-9]{64}$/u.test(digest), 'complete lowercase source hash required'); return digest;
}
function caseIdentity(root: string, value: unknown): string {
  const raw = record(value), file = text(raw['file']), fullName = text(raw['fullName']);
  const absolute = resolve(root, file);
  requireObservation(inside(root, absolute), 'selected test path escapes the source root');
  requireObservation(!/CP-006\/R6(?:\s|$)/u.test(fullName), 'completed selection cannot include the still-running reference');
  return JSON.stringify([relative(root, absolute).split(sep).join('/'), fullName]);
}

export interface ValidationSummary { cases: number; reports: number; sourceSha256: string; invocation: string; artifactHashes: string[]; totalMs: number; longestShardMs: number; criticalPathMs: number }

/** Read original evidence only. This neither runs commands nor creates a runner. */
export function verifyValidationObservations(input = process.env['FLUXWARDEN_LAB_VALIDATION_PLAN']): ValidationSummary {
  try { return verify(input); }
  catch (error) {
    if (error instanceof LabInvalidError) throw error;
    throw new LabInvalidError('validation observation plan or original artifact is unreadable or malformed');
  }
}
function verify(input: string | undefined): ValidationSummary {
  requireObservation(input && isAbsolute(input), 'absolute independent validation observation plan required');
  const planPath = resolve(input);
  requireObservation(realpathSync(planPath) === planPath && !lstatSync(planPath).isSymbolicLink() && lstatSync(planPath).isFile(), 'validation plan must be an ordinary canonical file');
  requireObservation(lstatSync(planPath).size <= 1024 * 1024, 'validation plan exceeds bounded input size');
  const plan = record(readJson(planPath));
  requireObservation(plan['version'] === 1 && plan['authorized'] === true, 'explicit version 1 observation authorization required');
  const declaredRoot = text(plan['evidenceRoot']);
  requireObservation(isAbsolute(declaredRoot), 'absolute owned evidence root required');
  const root = resolve(declaredRoot);
  requireObservation(realpathSync(root) === root && lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink() && dirname(root) !== root && inside(root, planPath), 'plan must belong to its canonical owned evidence root');
  const sourceRoot = text(plan['sourceRoot']);
  requireObservation(isAbsolute(sourceRoot) && dirname(resolve(sourceRoot)) !== resolve(sourceRoot), 'explicit bounded original source root required');
  const current = record(plan['current']), invocation = text(current['invocation']), sourceSha256 = sourceIdentity(current['sourceSha256']);
  const window = interval(current);
  requireObservation(window.finishedAt <= Date.now() && window.startedAt > 0, 'completed current invocation timestamps required');
  const seenArtifacts = new Set<string>(), artifactHashes: string[] = [];
  function artifact(value: unknown): { file: string; value: unknown } {
    const descriptor = record(value), file = ownedFile(root, descriptor['file']);
    requireObservation(!seenArtifacts.has(file), 'original observation artifact supplied more than once'); seenArtifacts.add(file);
    const bytes = readFileSync(file), digest = createHash('sha256').update(bytes).digest('hex');
    requireObservation(digest === sourceIdentity(descriptor['sha256']), 'original observation artifact hash mismatch');
    artifactHashes.push(digest); return { file: relative(root, file).split(sep).join('/'), value: JSON.parse(bytes.toString('utf8')) as unknown };
  }
  function sameInvocation(raw: RecordValue): void {
    requireObservation(raw['invocation'] === invocation && raw['sourceSha256'] === sourceSha256, 'stale invocation or mismatched original source identity');
  }
  const inventory = record(artifact(plan['inventory']).value); sameInvocation(inventory);
  requireObservation(number(inventory['collectedAt']) > 0 && number(inventory['collectedAt']) <= window.startedAt, 'independent selection must be collected before execution');
  const expected = list(inventory['cases']).map(value => caseIdentity(sourceRoot, value));
  requireObservation(expected.length > 0 && new Set(expected).size === expected.length, 'independent selection must be nonempty and unique');
  const observations = record(artifact(plan['observations']).value); sameInvocation(observations);
  const observedWindow = interval(observations);
  requireObservation(observedWindow.startedAt === window.startedAt && observedWindow.finishedAt === window.finishedAt, 'current invocation interval mismatch');
  const phases = record(observations['phases']), timings = new Map<Stage, Interval>();
  let previous = window.startedAt;
  for (const stage of stages) {
    const measured = interval(phases[stage]);
    requireObservation(measured.startedAt >= previous && measured.finishedAt <= window.finishedAt, 'phase intervals overlap, reverse or escape the invocation');
    timings.set(stage, measured); previous = measured.finishedAt;
  }
  requireObservation(timings.get('build')?.startedAt === window.startedAt && timings.get('leak')?.finishedAt === window.finishedAt, 'total must include original build through final leak observation');
  const commands: Command[] = list(observations['commands']).map(value => {
    const raw = record(value), measured = interval(raw), phase = text(raw['phase']);
    requireObservation(stages.some(stage => stage === phase), 'unknown measured command phase');
    const stage = phase as Stage, bound = timings.get(stage);
    requireObservation(bound && measured.startedAt >= bound.startedAt && measured.finishedAt <= bound.finishedAt, 'command interval escapes its measured phase');
    requireObservation(raw['exitCode'] === 0 && raw['signal'] === null, 'failed or signalled original subprocess cannot qualify');
    requireObservation(measured.finishedAt - measured.startedAt <= 180000, 'original subprocess exceeded its documented general budget');
    const argv = list(raw['argv']); requireObservation(argv.length > 0, 'original command identity required'); argv.forEach(text);
    const result: Command = { ...measured, phase: stage };
    if (raw['report'] !== undefined) result.report = text(raw['report']).split('\\').join('/');
    requireObservation(stage === 'run' || result.report === undefined, 'only selected test execution may supply a Vitest report');
    return result;
  });
  requireObservation(commands.filter(command => command.phase === 'build').length === 1, 'exactly one successful original build required');
  const runs = commands.filter(command => command.phase === 'run');
  requireObservation(runs.length > 0 && runs.every(command => command.report !== undefined), 'every original selected shard requires a report');
  requireObservation(commands.some(command => command.phase === 'leak'), 'original leak subprocess observation required');
  const build = commands.find(command => command.phase === 'build'), buildPhase = timings.get('build'), runPhase = timings.get('run');
  requireObservation(build && buildPhase && build.startedAt === buildPhase.startedAt && build.finishedAt === buildPhase.finishedAt, 'build phase must measure the one original build');
  requireObservation(runPhase && Math.min(...runs.map(command => command.startedAt)) === runPhase.startedAt && Math.max(...runs.map(command => command.finishedAt)) === runPhase.finishedAt, 'run phase must cover the actual shard interval');
  const actual: string[] = [];
  const reportDescriptors = list(plan['reports']);
  requireObservation(reportDescriptors.length === runs.length, 'original report count must match shard commands');
  const usedReports = new Set<string>();
  for (const descriptor of reportDescriptors) {
    const original = artifact(descriptor), report = record(original.value);
    const matching = runs.filter(command => command.report === original.file);
    requireObservation(matching.length === 1 && !usedReports.has(original.file), 'each original report must bind exactly one subprocess'); usedReports.add(original.file);
    const command = matching[0]; requireObservation(command, 'original report command required');
    requireObservation(number(report['startTime']) >= command.startedAt && number(report['startTime']) <= command.finishedAt, 'stale original Vitest report timestamp');
    const files = list(report['testResults']); requireObservation(files.length > 0, 'original Vitest shard must be nonempty');
    let count = 0, minimumSuites = files.length;
    for (const entry of files) {
      const file = record(entry); requireObservation(file['status'] === 'passed', 'nonpassing original test file');
      requireObservation(reporterMilliseconds(file['startTime']) >= command.startedAt && reporterMilliseconds(file['endTime']) <= command.finishedAt && reporterMilliseconds(file['endTime']) >= reporterMilliseconds(file['startTime']), 'test file timestamp outside the original subprocess');
      const assertions = list(file['assertionResults']); requireObservation(assertions.length > 0, 'original test file has no results');
      const observedSuites = new Set<string>();
      for (const result of assertions) {
        const assertion = record(result); requireObservation(assertion['status'] === 'passed' && list(assertion['failureMessages']).length === 0, 'skipped pending invalid or failed original case');
        reporterMilliseconds(assertion['duration']);
        const displayName = reportedCaseName(assertion);
        const ancestors = assertion['ancestorTitles'] as string[];
        for (let length = 1; length <= ancestors.length; ++length) {
          const prefix = ancestors.slice(0, length).filter(title => title !== '');
          if (prefix.length) observedSuites.add(JSON.stringify(prefix));
        }
        actual.push(caseIdentity(sourceRoot, { file: file['name'], fullName: displayName })); ++count;
      }
      minimumSuites += observedSuites.size;
    }
    const totalSuites = number(report['numTotalTestSuites']), passedSuites = number(report['numPassedTestSuites']);
    // Reporter suites include describe blocks. Empty/repeated names are not
    // fully recoverable from assertions; observed structural paths give a minimum.
    requireObservation(report['numTotalTests'] === count && report['numPassedTests'] === count && totalSuites >= minimumSuites && passedSuites === totalSuites, 'original Vitest summary disagrees with individual results');
    for (const key of ['numFailedTests', 'numPendingTests', 'numTodoTests', 'numFailedTestSuites', 'numPendingTestSuites']) requireObservation(report[key] === 0, 'original report contains failed pending or todo results');
    requireObservation(report['success'] === true, 'original Vitest report did not succeed');
  }
  requireObservation(actual.length === expected.length && new Set(actual).size === actual.length && expected.every(identity => actual.includes(identity)), 'selected case union has missing extra or duplicate identities');
  const measurements = record(observations['measurements']);
  for (const stage of stages) {
    const measured = timings.get(stage); requireObservation(measured && number(measurements[`${stage}Ms`]) === measured.finishedAt - measured.startedAt, 'phase measurement disagrees with original timestamps');
  }
  const totalMs = number(measurements['totalMs']), longestShardMs = number(measurements['longestShardMs']), criticalPathMs = number(measurements['criticalPathMs']);
  requireObservation(totalMs === window.finishedAt - window.startedAt && totalMs > 0, 'total must measure the complete original invocation');
  requireObservation(longestShardMs === Math.max(...runs.map(command => command.finishedAt - command.startedAt)), 'longest shard measurement disagrees with original subprocesses');
  // These observed serial phases surround the overlapping shards. Their full
  // elapsed span, including waits between phases, is the validation critical path.
  requireObservation(criticalPathMs === window.finishedAt - window.startedAt, 'critical path must include original setup run teardown and leak');
  return { cases: actual.length, reports: reportDescriptors.length, sourceSha256, invocation, artifactHashes, totalMs, longestShardMs, criticalPathMs };
}
