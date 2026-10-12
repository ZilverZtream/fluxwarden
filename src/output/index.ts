// The only module that writes to stdout and stderr (ARCHITECTURE.md §2 rule B4, SECURITY.md INV-11).
// The current CLI renders fixed texts and never passes input or exception details to this module.

export type Stream = 'stdout' | 'stderr';

export interface Output {
  /** Writes `text` to one stream; `done` runs once the write is handed off or has failed. */
  write(stream: Stream, text: string, done?: () => void): void;
  /** True once a write to `stream` reached the stream (the process's document or report is out). */
  wrote(stream: Stream): boolean;
}

export interface ErrorBody {
  readonly code: number;
  readonly step: string | null;
  readonly message: string;
}

/** The `--json` document (SPEC.md §10.1). `ok` is false exactly when `error` is not null. */
export interface Envelope {
  readonly schema: 1;
  readonly command: string | null;
  readonly ok: boolean;
  readonly warnings: readonly string[];
  readonly result: Readonly<Record<string, string>> | null;
  readonly error: ErrorBody | null;
}

export function envelope(command: string | null, result: Readonly<Record<string, string>> | null, error: ErrorBody | null): Envelope {
  return { schema: 1, command, ok: error === null, warnings: [], result: error === null ? result : null, error };
}

/** One JSON document on one line, newline-terminated. */
export function renderEnvelope(doc: Envelope): string {
  return `${JSON.stringify(doc)}\n`;
}

/** Output bound to the process streams. */
export function processOutput(): Output {
  // A reader that has gone away (EPIPE, a closed pipe) leaves nobody to report to; the exit code
  // still carries the result, and the stream error must not become an uncaught exception.
  const ignore = (): void => undefined;
  process.stdout.on('error', ignore);
  process.stderr.on('error', ignore);
  const wrote = { stdout: false, stderr: false };
  return {
    write(stream, text, done) {
      const target = stream === 'stdout' ? process.stdout : process.stderr;
      if (target.destroyed || !target.writable) {
        done?.();
        return;
      }
      // The text counts as out before write() is called, so a signal or failure handled
      // synchronously inside the write already sees the document as emitted.
      const previously = wrote[stream];
      wrote[stream] = true;
      const before = bytesWritten(target);
      let returned = false;
      try {
        target.write(text, () => done?.());
        returned = true;
      } finally {
        // A write that threw did not hand the text off. A pipe or terminal counts the bytes it
        // accepted (sent or buffered); a write that never reached it is not output. A file stream
        // has no counter: a write that returned counts.
        const after = bytesWritten(target);
        if (!returned || (before !== undefined && after !== undefined && after <= before)) wrote[stream] = previously;
      }
    },
    wrote(stream) {
      return wrote[stream];
    },
  };
}

function bytesWritten(target: NodeJS.WriteStream): number | undefined {
  // Typed as a net.Socket, but stdout redirected to a file is a stream without this counter.
  const value: unknown = target.bytesWritten;
  return typeof value === 'number' ? value : undefined;
}
