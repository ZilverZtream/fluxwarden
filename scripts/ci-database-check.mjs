import { createHash } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { basename, dirname, join, parse, relative, resolve } from 'node:path';
import { createPrivateDirectory, assertPrivateDirectories } from './private-scratch.mjs';
import { openDatabase } from '../dist/persistence/index.js';
import { currentUserSid, readSecurityDescriptors, restrictToOwner } from '../dist/platform/owner-only.js';
const parent = resolve(process.env.FLUXWARDEN_TEST_TMP);
const privateDirectories = [];
function diagnose(stage) {
  if (process.platform !== 'win32') return;
  const paths = [parse(parent).root, ...privateDirectories];
  const descriptors = readSecurityDescriptors(paths);
  console.log(JSON.stringify({ stage, identity: currentUserSid(), directories: descriptors.map((descriptor, index) => ({
    path: paths[index], owner: descriptor.ownerSid, dacl: descriptor.sddl.slice(0, 2048),
    daclTruncated: descriptor.sddl.length > 2048,
    daclSha256: createHash('sha256').update(descriptor.sddl).digest('hex'),
  })) }));
}
if (process.platform === 'win32') {
  const ownedRoot = process.env.FLUXWARDEN_CI_OWNED_ROOT;
  if (!ownedRoot || !/^fluxwarden-ci-[A-Za-z0-9]{6}$/.test(basename(ownedRoot))) throw new Error('the newly created CI root is required');
  privateDirectories.push(resolve(ownedRoot), parent, resolve(process.env.FLUXWARDEN_SENTINEL_DIR), resolve(process.env.FLUXWARDEN_EVIDENCE_DIR), resolve(process.env.TEMP), resolve(process.env.TMP), resolve(process.env.FLUXWARDEN_CI_CAPTURE_DIR));
  if (privateDirectories.slice(1).some(path => dirname(path) !== privateDirectories[0])) throw new Error('private CI children escaped their newly created root');
  diagnose('private CI ownership before restriction');
  await assertPrivateDirectories(privateDirectories);
  try {
    for (const directory of privateDirectories) restrictToOwner(directory, 'directory', {});
  } catch (error) {
    diagnose('private CI ownership restriction failed');
    throw error;
  }
  diagnose('private CI ownership after restriction');
  await assertPrivateDirectories(privateDirectories);
}
const scratch = await createPrivateDirectory(parent, 'ci-database-smoke-');
const child = relative(parent, scratch);
if (!child || child.startsWith('..') || resolve(parent, child) !== scratch) throw new Error('database smoke scratch escaped its parent');
try {
  const path = join(scratch, 'state', 'fluxwarden.sqlite');
  const writer = openDatabase(path, { readOnly: false });
  try {
    const pragmas = writer.pragmas();
    if (pragmas.journalMode !== 'wal' || pragmas.synchronous !== 2) throw new Error('database smoke durability check failed');
  } finally { writer.close(); }
  const reader = openDatabase(path, { readOnly: true });
  try { reader.nodes.list(); } finally { reader.close(); }
  console.log('Private database path smoke passed');
} catch (error) {
  diagnose('private database path smoke failed');
  throw error;
} finally {
  await assertPrivateDirectories([scratch]);
  await rm(scratch, { recursive: true, force: true });
}
