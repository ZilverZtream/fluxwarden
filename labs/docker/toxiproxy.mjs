// API paths and static population follow Shopify/toxiproxy v2.12.0 README.md.
// Supported types follow its toxics/toxic.go registry and toxics/*.go implementations.
const types = new Set(['latency', 'bandwidth', 'slow_close', 'timeout', 'reset_peer', 'slicer', 'limit_data']);

function failure(operation, reason, status) {
  const error = new Error(`toxiproxy ${operation}: ${reason}`);
  error.operation = operation;
  if (status !== undefined) error.status = status;
  return error;
}

export function createToxiproxyClient({ url, fetch: requestFetch = globalThis.fetch, timeoutMs = 5000, signal }) {
  let endpoint;
  try { endpoint = new URL(url); }
  catch { throw failure('configure', 'invalid control endpoint'); }
  if (endpoint.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost'].includes(endpoint.hostname) ||
      endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash) {
    throw failure('configure', 'loopback HTTP control endpoint required');
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || typeof requestFetch !== 'function') {
    throw failure('configure', 'positive finite deadline and fetch required');
  }

  async function request(operation, method, path, body) {
    const controller = new AbortController();
    let timer, rejectCancellation;
    const cancellation = new Promise((_resolve, reject) => { rejectCancellation = reject; });
    const cancel = reason => {
      // Neither the caller's abort reason nor a fetch exception becomes an error cause.
      rejectCancellation(failure(operation, reason));
      controller.abort();
    };
    const abort = () => cancel('aborted');
    const started = performance.now();
    const tick = () => {
      const remaining = timeoutMs - (performance.now() - started);
      if (remaining <= 0) cancel('deadline exceeded');
      else timer = setTimeout(tick, Math.min(remaining, 2147483647));
    };
    try {
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) { abort(); return await cancellation; }
      tick();
      const action = async () => {
        let response;
        try {
          response = await requestFetch(`${endpoint.origin}${path()}`, {
            method, signal: controller.signal, redirect: 'error',
            ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
          });
        } catch { throw failure(operation, 'request failed'); }
        if (!response.ok) {
          // Do not read hostile error bodies; cancellation also releases the connection.
          controller.abort();
          throw failure(operation, 'HTTP failure', response.status);
        }
        if (response.status === 204) return undefined;
        try { return await response.json(); }
        catch { throw failure(operation, 'invalid JSON response', response.status); }
      };
      return await Promise.race([cancellation, action()]);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
  }

  const proxy = name => `/proxies/${encodeURIComponent(name)}`;
  return {
    list: () => request('list', 'GET', () => '/proxies'),
    populate: proxies => request('populate', 'POST', () => '/populate', proxies),
    enable: (name, enabled = true) => request('enable', 'POST', () => proxy(name), { enabled }),
    add: (name, toxic) => {
      if (!types.has(toxic?.type)) return Promise.reject(failure('add', 'unsupported toxic type'));
      return request('add', 'POST', () => `${proxy(name)}/toxics`, toxic);
    },
    remove: (name, toxicName) => request('remove', 'DELETE', () => `${proxy(name)}/toxics/${encodeURIComponent(toxicName)}`),
    reset: () => request('reset', 'POST', () => '/reset'),
    version: () => request('version', 'GET', () => '/version'),
  };
}
