// Interface: task-owned SQLite through the existing persistence port; versioned decisions are immutable (INV-09).
import { beforeAll, expect, it } from 'vitest';
import { loadPersistence, prepareEmptyDatabaseFixture, raw, scratchDb, seedBase } from '../helpers/cp028-executor.js';

let emptyDatabase: string;
beforeAll(async () => { emptyDatabase = prepareEmptyDatabaseFixture(await loadPersistence()); });

for (const statement of [
  "UPDATE policy_versions SET policy_canonical_json = '{\"changed\":true}' WHERE id = ?",
  'DELETE FROM policy_versions WHERE id = ?',
  "INSERT OR REPLACE INTO policy_versions SELECT id, version_no, policy_sha256, '{\"changed\":true}', author, created_at FROM policy_versions WHERE id = ?",
]) {
  it(`CP-015/B6 REG-PERS008 versioned policy audit inputs refuse ${String(statement.split(' ')[0])} and retain their original contents (INV-09)`, async () => {
    const p = await loadPersistence();
    const path = scratchDb('policy-audit');
    const base = seedBase(p, path, emptyDatabase);
    const db = raw(path);
    try {
      const before = db.prepare('SELECT * FROM policy_versions WHERE id = ?').get(base.policyVersionId);
      expect(before).toBeDefined();
      expect(() => db.prepare(statement).run(base.policyVersionId)).toThrow();
      expect(db.prepare('SELECT * FROM policy_versions WHERE id = ?').get(base.policyVersionId)).toEqual(before);
    } finally { db.close(); }
  });
}
