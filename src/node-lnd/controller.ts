import { openLndRest, type LndRestOptions } from './rest.js';
import { LndRouteApi } from './routes.js';
import { LndExecutionAdapter } from './execute.js';
import { LndReadApi } from './api.js';

export async function openLndController(options: LndRestOptions, deadlineMs: number) {
  const rest = await openLndRest(options);
  return {
    fingerprints: rest.fingerprints,
    accounting: new LndReadApi(rest),
    execution: new LndExecutionAdapter(rest, { trackDeadlineMs: deadlineMs }),
    routes: new LndRouteApi(rest),
  };
}
