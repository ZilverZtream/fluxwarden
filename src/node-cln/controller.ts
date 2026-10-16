import { randomUUID } from 'node:crypto';
import { openClnRest, type ClnRestOptions } from './rest.js';
import { ClnRouteApi } from './routes.js';
import { ClnExecutionAdapter } from './execute.js';
import { ClnReadApi } from './api.js';
import type { RouteConstraints } from '../core/route.js';
import { channelScid } from '../core/scid.js';

export async function openClnController(options: ClnRestOptions, ownId: string, deadlineMs: number) {
  const rest = await openClnRest(options);
  const routes = new ClnRouteApi(rest);
  return {
    fingerprints: rest.fingerprints,
    accounting: new ClnReadApi(rest),
    execution: new ClnExecutionAdapter(rest, { ownId, waitChunkSeconds: 10, attemptDeadlineMs: deadlineMs }),
    routes: { buildCircularRoute: (constraints: RouteConstraints) => routes.buildCircularRoute(constraints, { layer: `fluxwarden-${randomUUID()}`,
      excludeScids: (constraints.excludeChannels ?? []).flatMap(key => { const scid = channelScid(key); return scid === null ? [] : [scid]; }) }) },
  };
}
