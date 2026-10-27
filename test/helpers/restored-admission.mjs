// A fresh process observes the public admission port, not a private SQLite table.
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const { openDatabase } = await import(pathToFileURL(resolve(root, 'dist/persistence/index.js')).href);
let db;
try {
  db = openDatabase(process.argv[2], { readOnly: false, mustExist: true });
  try { db.state.assertAdmitted(); process.stdout.write('{"admitted":true}\n'); }
  catch (error) {
    if (error?.code !== 'RESTORE_PENDING') throw error;
    process.stdout.write('{"admitted":false,"code":"RESTORE_PENDING"}\n');
  }
} catch (error) {
  process.stdout.write(`${JSON.stringify({ error: error?.name ?? 'unknown', code: error?.code ?? null })}\n`);
  process.exitCode = 1;
} finally { db?.close(); }
