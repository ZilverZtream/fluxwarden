// LND channel listings are normalized by the pure readers in core, so the arithmetic is shared with tests and tools.
export { normalizeLndChannel, normalizeLndPendingChannel, type LndPendingKind, type NormalizedChannel } from '../core/normalize.js';
