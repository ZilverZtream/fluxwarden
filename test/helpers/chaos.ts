/** CP-007 public helper. Cleanup is limited to the explicit owned proxies (D41). */
export interface Toxic { name: string; type: string; stream?: string; toxicity?: number; attributes: Record<string, unknown> }
export interface ProxyState { name: string; enabled: boolean; toxics: Toxic[]; listen?: string; upstream?: string }
export interface ChaosClient {
  list(): Promise<Record<string, ProxyState>>;
  enable(name: string, enabled?: boolean): Promise<unknown>;
  add(name: string, toxic: Toxic): Promise<unknown>;
  remove(name: string, toxicName: string): Promise<unknown>;
}
export class LabInvalidError extends Error {
  constructor(reason: string) { super(reason); this.name = 'LabInvalidError'; }
}
interface Options { client: ChaosClient; proxies: readonly string[]; setup: (client: ChaosClient) => unknown; signal?: AbortSignal; timeoutMs?: number }
const queues = new WeakMap<ChaosClient, Promise<void>>();

function deadline<T>(action: () => Promise<T>, ms: number, signal?: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const end = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); };
    const abort = () => { end(); reject(new Error('chaos operation aborted')); };
    const timer = setTimeout(() => { end(); reject(new Error('chaos operation deadline exceeded')); }, ms);
    if (signal?.aborted) { abort(); return; }
    signal?.addEventListener('abort', abort, { once: true });
    void Promise.resolve().then(action).then(value => { end(); resolve(value); }, (error: unknown) => { end(); reject(error instanceof Error ? error : new Error('chaos operation failed')); });
  });
}
function requireOwned(state: Record<string, ProxyState>, names: readonly string[], clean: boolean): void {
  for (const name of names) {
    const proxy = state[name];
    if (!proxy || proxy.name !== name || typeof proxy.enabled !== 'boolean' || !Array.isArray(proxy.toxics)) throw new LabInvalidError('owned proxy observation is incomplete');
    if (clean && (!proxy.enabled || proxy.toxics.length !== 0)) throw new LabInvalidError('owned proxy remains disabled or toxic');
  }
}
export async function withChaos<T>({ client, proxies, setup, signal, timeoutMs = 5000 }: Options, body: (client: ChaosClient) => T | Promise<T>): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || proxies.length === 0 || new Set(proxies).size !== proxies.length || proxies.some(name => !name)) throw new LabInvalidError('explicit owned proxies and a positive finite deadline are required');
  const previous = queues.get(client) ?? Promise.resolve();
  let release!: () => void;
  const turn = new Promise<void>(resolve => { release = resolve; });
  const tail = previous.then(() => turn);
  queues.set(client, tail);
  await previous;
  let active = true;
  const pending = new Set<Promise<unknown>>();
  const track = <T>(operation: () => Promise<T>): Promise<T> => {
    const call = Promise.resolve().then(operation); pending.add(call);
    void call.then(() => { pending.delete(call); }, () => { pending.delete(call); });
    return call;
  };
  const owns = (name: string) => { if (!active || !proxies.includes(name)) throw new LabInvalidError('chaos mutation is outside the active owned proxies'); };
  const scoped: ChaosClient = {
    list: () => { if (!active) return Promise.reject(new LabInvalidError('chaos operation ended')); return track(() => client.list()); },
    enable: (name, enabled = true) => { owns(name); return track(() => client.enable(name, enabled)); },
    add: (name, toxic) => { owns(name); return track(() => client.add(name, toxic)); },
    remove: (name, toxicName) => { owns(name); return track(() => client.remove(name, toxicName)); },
  };
  let result: T | undefined, failure: unknown, failed = false;
  try {
    result = await deadline(async () => {
      requireOwned(await scoped.list(), proxies, true);
      await setup(scoped);
      return await body(scoped);
    }, timeoutMs, signal);
  } catch (error) { failure = error; failed = true; }
  active = false;
  let restorationFailed = false;
  // A request still mutating after restoration cannot provide a clean result.
  try { await deadline(async () => { await Promise.allSettled([...pending]); }, timeoutMs); }
  catch { restorationFailed = true; }
  try {
    await deadline(async () => {
      const observed = await client.list();
      requireOwned(observed, proxies, false);
      const attempts = proxies.flatMap(name => [
        Promise.resolve().then(() => client.enable(name, true)),
        ...(observed[name]?.toxics ?? []).map(toxic => Promise.resolve().then(() => client.remove(name, toxic.name))),
      ]);
      if ((await Promise.allSettled(attempts)).some(result => result.status === 'rejected')) restorationFailed = true;
    }, timeoutMs);
  } catch { restorationFailed = true; }
  // This independent read is attempted even when mutation cleanup throws or expires.
  try { requireOwned(await deadline(() => client.list(), timeoutMs), proxies, true); }
  catch { restorationFailed = true; }
  finally { release(); if (queues.get(client) === tail) queues.delete(client); }
  if (restorationFailed) throw new LabInvalidError('owned proxy restoration could not be verified');
  if (failed) throw failure;
  return result as T;
}
