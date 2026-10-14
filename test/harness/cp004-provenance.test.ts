import { it } from 'vitest';
import { verifyProvenance } from '../helpers/cp004-provenance.js';

it('CP-004/B6 source provenance and notice retain licensing every source hash and exact imported file identity', () => {
  verifyProvenance();
});
