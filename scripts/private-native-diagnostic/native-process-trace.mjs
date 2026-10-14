// Private diagnostic only. Preserve native arguments, input, output, errors and limits.
import childProcess from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { performance } from 'node:perf_hooks';

const directory = process.env.FLUXWARDEN_NATIVE_TRACE_DIR;
if (!directory) throw new Error('a prepared private native trace directory is required');
const installed = Symbol.for('fluxwarden.private.native-process-trace');
if (!childProcess.execFileSync[installed]) {
  const original = childProcess.execFileSync;
  let sequence = 0;
  function record(row) {
    // A diagnostic failure must never change the product call or its result.
    try { appendFileSync(join(directory, `node-${process.pid}.jsonl`), JSON.stringify({ processId: process.pid, ...row }) + '\n'); } catch { /* Missing rows are reported separately. */ }
  }
  childProcess.execFileSync = function (file, args, options) {
    if (typeof file !== 'string' || !Array.isArray(args)) return original.apply(this, arguments);
    const parameters = [...args];
    const powershell = /powershell\.exe$/i.test(file);
    const command = parameters.indexOf('-Command') + 1;
    const script = powershell && command > 0 && typeof parameters[command] === 'string' ? parameters[command] : '';
    let operation = /whoami\.exe$/i.test(file) ? 'whoami' : /icacls\.exe$/i.test(file) ? 'icacls' : 'other-system-tool';
    if (script.includes('RawSecurityDescriptor')) operation = 'readSecurityDescriptors';
    if (script.includes('$request.operation') && script.includes('[IO.FileMode]::CreateNew')) {
      try {
        const request = JSON.parse(options?.input?.toString());
        operation = request.operation === 'create-empty-file' ? 'createOwnerOnlyEmptyFile'
          : request.operation === 'create-directory' ? 'createOwnerOnlyDirectory' : 'other-system-tool';
      } catch { /* The original operation remains responsible for input validation. */ }
    }
    const id = ++sequence;
    let prepared = options;
    if (powershell && command > 0 && operation !== 'other-system-tool') {
      const prefix = '$fwCpuStart=[Diagnostics.Process]::GetCurrentProcess().TotalProcessorTime.TotalMilliseconds; $fwScriptClock=[Diagnostics.Stopwatch]::StartNew(); try { ';
      const suffix = ` } finally { try { $fwCulture=[Globalization.CultureInfo]::InvariantCulture; $fwCpuEnd=[Diagnostics.Process]::GetCurrentProcess().TotalProcessorTime.TotalMilliseconds; $fwRow='{"operation":"${operation}","processId":'+$env:FLUXWARDEN_NATIVE_PROFILE_PARENT+',"sequence":'+$env:FLUXWARDEN_NATIVE_PROFILE_SEQUENCE+',"childProcessId":'+$PID+',"startupCpuMs":'+$fwCpuStart.ToString($fwCulture)+',"finalCpuMs":'+$fwCpuEnd.ToString($fwCulture)+',"scriptWallMs":'+$fwScriptClock.Elapsed.TotalMilliseconds.ToString($fwCulture)+'}'; $fwFile=[IO.Path]::Combine($env:FLUXWARDEN_NATIVE_TRACE_DIR,'cpu-'+$env:FLUXWARDEN_NATIVE_PROFILE_PARENT+'-'+$env:FLUXWARDEN_NATIVE_PROFILE_SEQUENCE+'.json'); [IO.File]::WriteAllText($fwFile,$fwRow+[Environment]::NewLine,[Text.UTF8Encoding]::new($false)); } catch { } $null=[Math]::Abs(0); }`;
      parameters[command] = prefix + script + suffix;
      prepared = { ...options, env: { ...(options?.env ?? process.env), FLUXWARDEN_NATIVE_TRACE_DIR: directory,
        FLUXWARDEN_NATIVE_PROFILE_PARENT: String(process.pid), FLUXWARDEN_NATIVE_PROFILE_SEQUENCE: String(id) } };
    }
    const began = performance.now();
    record({ sequence: id, operation, phase: 'native-start' });
    let failed = 1;
    try {
      const result = original.call(this, file, parameters, prepared);
      failed = 0;
      return result;
    } finally {
      record({ sequence: id, operation, phase: 'native-end', wallMs: performance.now() - began, failed });
    }
  };
  Object.defineProperty(childProcess.execFileSync, installed, { value: true });
  syncBuiltinESMExports();
}
