import type { ClnHandler } from './fake-cln.js';

/**
 * Independent pinned-node model: Core Lightning 26.06.9 commit
 * a2176589f235b63bc1a37e69362dfd6c925397e9, plugins/askrene/child/mcf.c:1409-1416.
 * https://raw.githubusercontent.com/ElementsProject/lightning/a2176589f235b63bc1a37e69362dfd6c925397e9/plugins/askrene/child/mcf.c
 * After bounded path search exhausts alternatives, finalcltv + flows_worst_delay > maxdelay
 * returns PAY_ROUTE_TOO_EXPENSIVE (206). Equality is allowed. No product arithmetic is used.
 */
export function askreneTotalDelay(worstFlowDelay: number, answer: Record<string, unknown>): ClnHandler {
  return (context, cln) => {
    const final = context.params['final_cltv'];
    const limit = context.params['maxdelay'];
    if (typeof final !== 'number' || typeof limit !== 'number') throw new Error('expected numeric CLTV parameters');
    if (final + worstFlowDelay > limit) {
      cln.rpcError(context, 'getroutes-excessive-delays', 206, 'Could not find route without excessive delays');
    } else {
      cln.result(context, 'getroutes', answer);
    }
  };
}
