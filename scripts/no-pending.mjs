// CI check over Vitest JSON reports: every test ran and passed. Vitest exits 0 with skipped or
// todo tests; this exits 1 when a report is missing, unreadable, empty, or holds a test whose
// status is not "passed" (skipped, pending, todo, failed).
// Usage: node scripts/no-pending.mjs <vitest-json-report>...
import { readFileSync } from 'node:fs';

const reports = process.argv.slice(2);
let failed = reports.length === 0;
if (failed) process.stderr.write('no-pending: no report given\n');

for (const path of reports) {
  let report;
  try {
    report = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    process.stderr.write(`no-pending: unreadable report ${path}\n`);
    failed = true;
    continue;
  }
  const files = Array.isArray(report?.testResults) ? report.testResults : [];
  let count = 0;
  for (const file of files) {
    const tests = Array.isArray(file?.assertionResults) ? file.assertionResults : [];
    if (tests.length === 0) {
      process.stderr.write(`no-pending: no test results in ${String(file?.name)}\n`);
      failed = true;
    }
    for (const test of tests) {
      count += 1;
      if (test?.status !== 'passed') {
        process.stderr.write(`no-pending: ${String(test?.status)}: ${String(file?.name)} ${String(test?.fullName ?? test?.title)}\n`);
        failed = true;
      }
    }
  }
  if (count === 0) {
    process.stderr.write(`no-pending: report ${path} holds no tests\n`);
    failed = true;
  }
}
process.exitCode = failed ? 1 : 0;
