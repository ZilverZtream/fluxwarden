import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TransportError } from '../core/errors.js';

export interface RuneCadence {
  readonly key: string;
  readonly intervalMs: number;
}

/**
 * Decode only permission timing, never authorization. Adapted from
 * ElementsProject/lightning@a2176589f235b63bc1a37e69362dfd6c925397e9:
 * ccan/ccan/rune/coding.c (32-byte state, escaped restrictions) and
 * lightningd/runes.c:78-150 (last-used unique id, 60e9/rate nanoseconds).
 * Other restrictions and invalid credentials remain the node's decision.
 */
export function runeCadence(bytes: Uint8Array, certificateFingerprint: string): RuneCadence | undefined {
  const text = Buffer.from(bytes).toString('utf8');
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(text)) return undefined;
  const decoded = Buffer.from(text, 'base64url');
  if (decoded.length < 32 || decoded.toString('base64url') !== text.replace(/=+$/, '')) return undefined;
  const encoded = decoded.subarray(32).toString('utf8');
  if (encoded.includes('\0')) return undefined;
  const restrictions: string[][] = [[]];
  let alternative = '';
  for (let index = 0; index < encoded.length; index++) {
    const character = encoded.charAt(index);
    if (character === '\\') {
      const escaped = encoded[++index];
      if (escaped === undefined) return undefined;
      alternative += escaped;
    } else if (character === '|' || character === '&') {
      restrictions[restrictions.length - 1]?.push(alternative);
      alternative = '';
      if (character === '&') restrictions.push([]);
    } else alternative += character;
  }
  restrictions[restrictions.length - 1]?.push(alternative);
  const first = restrictions[0];
  const identifier = first?.length === 1 ? /^=(\+?[0-9]+)(?:-.*)?$/.exec(first[0] ?? '')?.[1] : undefined;
  if (identifier === undefined) return undefined;
  const uniqueId = BigInt(identifier);
  if (uniqueId > 9223372036854775807n) return undefined;
  let intervalMs = 0;
  for (const restriction of restrictions.slice(1)) {
    // Conservatively honor every recognized rate alternative, even when another
    // alternative could grant this method. Admission never broadens permission.
    for (const item of restriction) {
      const value = /^rate=(\+?[0-9]+)$/.exec(item)?.[1];
      if (value === undefined) continue;
      const rate = BigInt(value);
      if (rate === 0n || rate >= 4294967295n) continue;
      intervalMs = Math.max(intervalMs, Number(60000000000n / rate) / 1000000);
    }
  }
  // Node-local ids also identify restricted descendants and file copies. Keep
  // only a digest, scoped to the pinned node CA, in process-wide scheduling state.
  const key = createHash('sha256').update(`${certificateFingerprint}\0${uniqueId.toString()}`).digest('hex');
  return { key, intervalMs };
}

export interface CadenceAdmission {
  written(transportMarginMs: number): void;
  answered(): void;
  done(): void;
}

interface Waiting {
  readonly intervalMs: number;
  readonly deadline: number;
  readonly resolve: (admission: CadenceAdmission) => void;
  readonly reject: (error: TransportError) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
}

const MAX_IDENTITIES = 4096;
const MAX_WAITING = 64;
// rate=1 is the longest valid rate interval. Keep idle usage across client reopen
// for this full period; clients look up the shared identity for every call.
const RETAIN_MS = 60001;
const states = new Map<string, AdmissionQueue>();
const expired = (): TransportError => new TransportError('CLN permission admission exceeded the call deadline', 'connect');

class AdmissionQueue {
  #lastUsed: number | undefined;
  #busy = false;
  #inFlight = 0;
  readonly #waiting: Waiting[] = [];
  #timer: ReturnType<typeof setTimeout> | undefined;

  idle(now: number): boolean {
    return !this.#busy && this.#inFlight === 0 && this.#waiting.length === 0 &&
      (this.#lastUsed === undefined || now - this.#lastUsed >= RETAIN_MS);
  }

  admit(intervalMs: number, deadline: number): Promise<CadenceAdmission> {
    if (this.#waiting.length >= MAX_WAITING) return Promise.reject(new TransportError('CLN permission admission queue is full', 'connect'));
    if (performance.now() >= deadline) return Promise.reject(expired());
    return new Promise((resolve, reject) => {
      const waiting: Waiting = { intervalMs, deadline, resolve, reject, timer: undefined };
      waiting.timer = setTimeout(() => {
        const index = this.#waiting.indexOf(waiting);
        if (index === -1) return;
        this.#waiting.splice(index, 1);
        reject(expired());
        this.#pump();
      }, Math.max(1, Math.ceil(deadline - performance.now())));
      this.#waiting.push(waiting);
      this.#pump();
    });
  }

  #pump(): void {
    clearTimeout(this.#timer);
    this.#timer = undefined;
    if (this.#busy) return;
    const head = this.#waiting[0];
    if (head === undefined) return;
    const now = performance.now();
    if (now >= head.deadline) {
      this.#waiting.shift();
      clearTimeout(head.timer);
      head.reject(expired());
      this.#pump();
      return;
    }
    // Round the permission interval up with one timer quantum of clearance.
    // Recheck monotonic time after every wake; never dispatch on an early timer.
    const next = this.#lastUsed === undefined ? now : this.#lastUsed + (head.intervalMs > 0 ? Math.ceil(head.intervalMs) + 1 : 0);
    if (next > now) {
      this.#timer = setTimeout(() => { this.#pump(); }, Math.max(1, Math.ceil(Math.min(next, head.deadline) - now)));
      return;
    }
    this.#waiting.shift();
    clearTimeout(head.timer);
    this.#busy = true;
    this.#inFlight++;
    let held = true, finished = false;
    const release = (): void => {
      if (!held) return;
      held = false;
      this.#busy = false;
      this.#pump();
    };
    head.resolve({
      written: transportMarginMs => {
        if (finished) return;
        // A client write precedes server authorization. Use the measured TLS
        // connection/write duration as a conservative transit margin while an
        // executing RPC with no response headers still permits concurrency.
        this.#lastUsed = Math.max(this.#lastUsed ?? 0, performance.now() + transportMarginMs);
        release();
      },
      // Response headers conservatively bound the authorization time without
      // waiting for the RPC body. A held first RPC must not block the next call.
      answered: () => { if (!finished) { this.#lastUsed = Math.max(this.#lastUsed ?? 0, performance.now()); this.#pump(); } },
      done: () => {
        if (finished) return;
        finished = true;
        this.#inFlight--;
        release();
      },
    });
  }
}

/** Shared by all in-process clients using the same node's rune unique id. */
export function admitRune(cadence: RuneCadence, deadline: number): Promise<CadenceAdmission> {
  let state = states.get(cadence.key);
  if (state === undefined) {
    const now = performance.now();
    for (const [key, candidate] of states) if (candidate.idle(now)) states.delete(key);
    if (states.size >= MAX_IDENTITIES) return Promise.reject(new TransportError('CLN permission admission identity limit reached', 'connect'));
    state = new AdmissionQueue();
    states.set(cadence.key, state);
  }
  return state.admit(cadence.intervalMs, deadline);
}
