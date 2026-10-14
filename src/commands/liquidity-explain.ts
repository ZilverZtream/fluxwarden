// `liquidity explain <proposal-id>`: the stored explanation tree of one proposal. Read-only, no node calls.
import { ExitCode } from '../core/exit-codes.js';
import { ULID } from '../core/ulid.js';
import { envelope, renderEnvelope, terminalText } from '../output/index.js';
import type { Database } from '../persistence/index.js';
import type { Clock } from '../planner/diagnose.js';
import { PROPOSAL_ID_PREFIX, renderProposal } from '../planner/proposal.js';
import { proposalDocument } from './proposal-document.js';

const COMMAND = 'liquidity explain';

export interface LiquidityExplainInput {
  readonly db: Database;
  /** `prop_<ULID>`. */
  readonly proposalId: string;
  readonly clock: Clock;
}

export interface CommandOutcome {
  readonly exitCode: number;
  readonly json: string;
  readonly text: string;
}

function invalid(message: string): CommandOutcome {
  return {
    exitCode: ExitCode.INVALID_INPUT,
    json: renderEnvelope(envelope(COMMAND, null, { code: ExitCode.INVALID_INPUT, step: null, message })),
    text: terminalText(`error: ${message}\n`),
  };
}

export function liquidityExplain(input: LiquidityExplainInput): CommandOutcome {
  const id = input.proposalId.startsWith(PROPOSAL_ID_PREFIX) ? input.proposalId.slice(PROPOSAL_ID_PREFIX.length) : null;
  if (id === null || !ULID.test(id)) return invalid(`a proposal id is ${PROPOSAL_ID_PREFIX} followed by a 26-character ULID`);
  const stored = input.db.proposals.find(id);
  if (stored === null) return invalid('no proposal has this id');
  const doc = proposalDocument(stored, input.clock.now());
  return {
    exitCode: ExitCode.SUCCESS,
    json: renderEnvelope(envelope(COMMAND, doc as unknown as Record<string, unknown>, null)),
    text: terminalText(renderProposal(doc)),
  };
}
