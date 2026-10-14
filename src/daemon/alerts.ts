import { createHash } from 'node:crypto';
import { lstatSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Secret } from '../core/secret.js';
import {
  effectContent, MAX_EFFECT_BYTES, prepareEffectDirectory, publishEffect, readEffect, type EffectFields,
} from '../output/effects.js';
import { createRedactor } from '../output/index.js';

/**
 * Alert files (SPEC.md §10.4 DM5): one HMAC-signed effect file per alert, written exclusively, redacted,
 * bounded in size and rate-limited. Each (kind, subject, state) has its own file, so an alert is written once
 * per state of its condition, also across restarts. A file at that path that does not verify under the key is
 * never taken for the alert and never overwritten: raise() throws.
 */

export type AlertKind = 'stuck-in-flight' | 'fee-mismatch' | 'delta-mismatch' | 'budget-overrun' | 'recon-difference'
  | 'invariant-breach' | 'node-quarantined';

export interface AlertInput {
  readonly kind: AlertKind;
  /** The execution id or node name. */
  readonly subject: string;
  /** The condition the alert reports, such as the execution status. */
  readonly state: string;
  readonly detail?: Readonly<Record<string, string>>;
}

export type RaiseResult = 'written' | 'duplicate' | 'rate-limited';

export interface AlertWriter { raise(alert: AlertInput): RaiseResult }

export interface AlertWriterOptions {
  readonly dir: string;
  /** The outbox HMAC key, 32 bytes. */
  readonly key: Uint8Array;
  /** The rate limit runs on this clock. */
  readonly monotonic: { now(): number };
  /** `raisedAt` comes from this clock; files written before a restart count against the window by it. */
  readonly clock: { now(): number };
  readonly maxPerWindow: number;
  readonly windowMs: number;
  readonly secrets: readonly Secret[];
}

export const MAX_FIELD_CHARS = 1024;
const KEY_BYTES = 32;

/** The first 1024 UTF-16 code units, never ending inside a surrogate pair. */
function cut(text: string): string {
  if (text.length <= MAX_FIELD_CHARS) return text;
  const end = /[\ud800-\udbff]/.test(text.charAt(MAX_FIELD_CHARS - 1)) ? MAX_FIELD_CHARS - 1 : MAX_FIELD_CHARS;
  return text.slice(0, end);
}

/** The file name of one alert: distinct for distinct (kind, subject, state), whatever characters they hold or how long. */
function alertName(kind: string, subject: string, state: string): string {
  return `${kind}-${createHash('sha256').update(JSON.stringify([kind, subject, state]), 'utf8').digest('hex').slice(0, 40)}`;
}

export function createAlertWriter(options: AlertWriterOptions): AlertWriter {
  if (options.key.byteLength !== KEY_BYTES) throw new Error('alerts: the outbox key is 32 bytes');
  if (!Number.isSafeInteger(options.maxPerWindow) || options.maxPerWindow < 1) throw new Error('alerts: maxPerWindow is a positive integer');
  if (!Number.isFinite(options.windowMs) || options.windowMs <= 0) throw new Error('alerts: windowMs is a positive duration');
  prepareEffectDirectory(options.dir);
  const redact = createRedactor(options.secrets);
  const clean = (text: string): string => cut(redact(text));
  const written = recentWrites(options);
  let suppressed = 0;

  return {
    raise(alert) {
      const fullSubject = redact(alert.subject);
      const fullState = redact(alert.state);
      const kind = clean(alert.kind);
      const subject = cut(fullSubject);
      const state = cut(fullState);
      const idempotencyKey = `${kind}:${subject}:${state}`;
      const name = alertName(kind, fullSubject, fullState);
      const path = join(options.dir, `${name}.json`);
      const existing = (): 'duplicate' | null => {
        const found = readEffect(path, options.key);
        if (found.state === 'absent') return null;
        if (found.state === 'valid' && found.fields['kind'] === kind && found.fields['subject'] === subject && found.fields['state'] === state) return 'duplicate';
        throw new Error(`alerts: ${name}.json exists and is not this alert's file under the outbox key`);
      };
      if (existing() !== null) return 'duplicate';
      const now = options.monotonic.now();
      while (written.length > 0 && (written[0] ?? now) <= now - options.windowMs) written.shift();
      if (written.length >= options.maxPerWindow) {
        suppressed += 1;
        return 'rate-limited';
      }
      const fields: EffectFields = { kind, idempotencyKey, subject, state, raisedAt: options.clock.now(), suppressed };
      const details = Object.entries(alert.detail ?? {}).map(([label, value]): [string, string] => [`detail.${clean(label)}`, clean(value)]);
      for (const [label, value] of details) fields[label] = value;
      let content = effectContent(options.key, fields);
      // A file stays within the effect bound: detail entries are dropped from the last until it fits.
      for (let i = details.length - 1; content.length > MAX_EFFECT_BYTES && i >= 0; i--) {
        const [label] = details[i] ?? [''];
        // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
        delete fields[label];
        content = effectContent(options.key, fields);
      }
      if (publishEffect(options.dir, name, content) === 'exists') {
        // Another writer wrote it first: its file decides.
        if (existing() !== null) return 'duplicate';
        throw new Error(`alerts: ${name}.json appeared while it was written`);
      }
      written.push(now);
      suppressed = 0;
      return 'written';
    },
  };
}

/**
 * The monotonic times of the valid alert files written within the last window, from their `raisedAt`, so a
 * restart does not reset the rate limit.
 */
function recentWrites(options: AlertWriterOptions): number[] {
  const clockNow = options.clock.now();
  const monotonicNow = options.monotonic.now();
  const since = clockNow - options.windowMs;
  const times: number[] = [];
  for (const name of readdirSync(options.dir)) {
    if (name.startsWith('.') || !name.endsWith('.json')) continue;
    const path = join(options.dir, name);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.mtimeMs < since - options.windowMs) continue;
    const read = readEffect(path, options.key);
    if (read.state !== 'valid') continue;
    const raisedAt = read.fields['raisedAt'];
    if (typeof raisedAt === 'number' && raisedAt > since && raisedAt <= clockNow) times.push(monotonicNow - (clockNow - raisedAt));
  }
  return times.sort((a, b) => a - b);
}
