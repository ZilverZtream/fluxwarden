/** DR2 checks the native capability before opening any database or contacting a node. */
export function sqliteAvailable(): boolean {
  const sqlite: unknown = process.getBuiltinModule('node:sqlite');
  return sqlite !== undefined;
}
