// Retrieve the original CI final tarball; a fresh pack is never its substitute.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, lstatSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { officialGitHub, repository, zipMembers } from './release-gate.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export async function retrieveCandidate(source, tarballPath, evidencePath, github) {
  if (!/^[a-f0-9]{40}$/.test(source)) throw new Error('release candidate: source required');
  const runs = await github.listRuns(source);
  for (const run of runs) {
    if (run.head_sha !== source || run.repository?.full_name !== repository || run.path !== '.github/workflows/ci.yml' || run.status !== 'completed' || run.conclusion !== 'success') continue;
    const artifacts = await github.listArtifacts(run.id);
    const evidence = artifacts.filter(a => a.name === 'fluxwarden-release-evidence' && a.expired === false);
    const packages = artifacts.filter(a => a.name === 'fluxwarden-final-package' && a.expired === false);
    if (evidence.length !== 1 || packages.length !== 1) continue;
    const archive = await github.getArtifact(packages[0].id), bytes = await github.downloadArtifact(archive.id);
    if (archive.expired || archive.workflow_run?.id !== run.id || archive.workflow_run?.head_sha !== source || archive.size_in_bytes !== bytes.length || archive.digest !== `sha256:${hash(bytes)}`) throw new Error('release candidate: archive authentication failed');
    const members = zipMembers(bytes);
    const version = JSON.parse(readFileSync('package.json', 'utf8')).version;
    const expected = `fluxwarden-${version}.tgz`;
    if (members.size !== 1 || !members.has(expected)) throw new Error('release candidate: exact final package required');
    const tarball = members.get(expected);
    // Replacing the locally rebuilt validation pack is explicit. Refuse links.
    try { if (!lstatSync(tarballPath).isFile() || lstatSync(tarballPath).isSymbolicLink()) throw new Error('release candidate: unsafe destination'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    writeFileSync(tarballPath, tarball, { mode: 0o600 });
    writeFileSync(evidencePath, JSON.stringify({ schemaVersion: 1, repository, sourceCommit: source,
      ci: { runId: run.id, runAttempt: run.run_attempt, workflowPath: '.github/workflows/ci.yml', artifactId: evidence[0].id },
      tarball: { sha256: hash(tarball), bytes: tarball.length } }) + '\n', { mode: 0o600, flag: 'wx' });
    return;
  }
  throw new Error('release candidate: no complete same-source CI evidence available');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 6 || args[0] !== '--source' || args[2] !== '--tarball' || args[4] !== '--evidence') throw new Error('release candidate: arguments required');
    await retrieveCandidate(args[1], resolve(args[3]), resolve(args[5]), officialGitHub(process.env.GITHUB_TOKEN));
  } catch { process.stderr.write('release candidate: authenticated final artifact unavailable\n'); process.exitCode = 1; }
}
