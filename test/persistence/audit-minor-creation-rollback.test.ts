// Interface: persistence.openDatabase; failed creation owns only directories it created.
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { descriptor, loadPersistence, makeOwnerOnlyDir, scratch } from '../helpers/cp015-persistence.js';

it('CP-015/B1 REG-PERS013 failed database creation preserves a preexisting parent and its permissions', async () => {
  const p = await loadPersistence();
  const root = scratch('creation-rollback');
  makeOwnerOnlyDir(root);
  const existing = join(root, 'existing');
  mkdirSync(existing, { mode: 0o700 });
  makeOwnerOnlyDir(existing);
  const before = descriptor(existing);
  const created = join(existing, 'new-state');
  // Every supported filesystem refuses an overlong final component. The existing ancestor remains caller-owned.
  expect(() => { p.openDatabase(join(created, 'x'.repeat(300) + '.db'), { readOnly: false }).close(); }).toThrow();
  expect(existsSync(existing)).toBe(true);
  expect(descriptor(existing)).toEqual(before);
  const good = p.openDatabase(join(existing, 'ordinary.db'), { readOnly: false });
  good.close();
  expect(existsSync(join(existing, 'ordinary.db'))).toBe(true);
});
