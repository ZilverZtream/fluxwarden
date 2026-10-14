import { ExitCode } from '../cli/exit-codes.js';
import type { Database } from '../persistence/index.js';
import { verifyLedger, type VerifyReport } from '../ledger/verify.js';

/** `ledger verify`: recomputes the books from the stored journals; any finding is an invariant breach. */
export function runLedgerVerify(db: Database): { exitCode: typeof ExitCode.SUCCESS | typeof ExitCode.INVARIANT_BREACH; report: VerifyReport } {
  const report = verifyLedger(db.ledger.book());
  return { exitCode: report.ok ? ExitCode.SUCCESS : ExitCode.INVARIANT_BREACH, report };
}
