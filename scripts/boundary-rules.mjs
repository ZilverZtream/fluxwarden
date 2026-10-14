import { isBuiltin } from 'node:module';
import { dirname, relative, resolve } from 'node:path';

// Node 22's builtinModules omits prefix-only modules such as node:sqlite.
// isBuiltin recognises them; retain the guard's normalised-name comparisons.
const builtin = name => isBuiltin(`node:${name}`);
const network = new Set(['http', 'https', 'http2', 'net', 'tls', 'dgram']);
// Internal builtins (_http_client, _tls_wrap, ...) reach the same network stack.
const networkBuiltin = name => network.has(name) || /^_(?:http|tls|stream_wrap)/.test(name);
const fileWrites = /^(?:write|append|truncate|createWriteStream|mkdir|mkdtemp|rm|rmdir|unlink|rename|copyFile|cp|link|symlink|chmod|chown|utimes)/;
// The single source module that may start a child process: it runs the system icacls.exe and
// whoami.exe by absolute path with fixed argument arrays to set owner-only permissions on Windows.
export const childProcessHost = 'src/platform/owner-only.ts';
const sql = /\b(?:SELECT\s+[\s\S]+?\s+FROM|INSERT\s+(?:OR\s+[A-Z]+\s+)?INTO|REPLACE\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|BEGIN\s+TRANSACTION|PRAGMA\s+)\b/i;

// Static text: literals, constant concatenation and, given the source, const bindings.
function literal(node, source, depth = 0) {
  if (!node || depth > 16) return null;
  if (node.type === 'Literal') return typeof node.value === 'string' ? node.value : null;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0].value.cooked;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = literal(node.left, source, depth + 1), right = literal(node.right, source, depth + 1);
    if (left !== null && right !== null) return left + right;
  }
  if (['TSAsExpression', 'TSNonNullExpression', 'TSSatisfiesExpression'].includes(node.type)) return literal(node.expression, source, depth + 1);
  if (node.type === 'Identifier' && source) {
    const binding = variable(source, node);
    const definition = binding?.defs.length === 1 ? binding.defs[0] : null;
    if (definition?.type === 'Variable' && definition.parent.kind === 'const' && definition.node.id.type === 'Identifier') {
      return literal(definition.node.init, source, depth + 1);
    }
  }
  return null;
}

function property(node, source) {
  return node.computed ? literal(node.property, source) : node.property.name;
}

// Reuse ESLint's scope-aware identifier lookup technique from
// eslint/eslint lib/rules/no-restricted-globals.js; local injected ports remain allowed.
function variable(source, node) {
  for (let scope = source.getScope(node); scope; scope = scope.upper) {
    const found = scope.set.get(node.name);
    if (found) return found;
  }
  return null;
}

function capabilities(source) {
  function capability(node, seen = new Set()) {
    if (!node || seen.has(node)) return null;
    seen = new Set(seen).add(node);
    if (['TSAsExpression', 'TSNonNullExpression', 'ChainExpression'].includes(node.type)) return capability(node.expression, seen);
    if (node.type === 'CallExpression') {
      // Reflect.get(object, key) reads a property; process.getBuiltinModule(name) is an import.
      const callee = capability(node.callee, seen)?.replace(/^(?:globalThis|global)\./, '');
      const key = literal(node.arguments[1], source), name = literal(node.arguments[0], source);
      if (callee === 'Reflect.get' && key !== null) {
        const base = capability(node.arguments[0], seen);
        return base ? `${base}.${key}` : null;
      }
      if (callee && /^(?:builtin:)?process\.getBuiltinModule$/.test(callee) && name !== null) {
        const imported = name.replace(/^node:/, '');
        return builtin(imported) ? `builtin:${imported}` : null;
      }
      return null;
    }
    if (node.type === 'MemberExpression') {
      const base = capability(node.object, seen), name = property(node, source);
      return base && name !== null ? `${base}.${name}` : null;
    }
    if (node.type !== 'Identifier') return null;
    const binding = variable(source, node);
    if (!binding?.defs.length) return node.name;
    if (binding.defs.length !== 1) return null;
    const definition = binding.defs[0];
    if (definition.type === 'ImportBinding') {
      const imported = definition.parent.source.value.replace(/^node:/, '');
      if (!builtin(imported)) return null;
      const specifier = definition.node;
      return `builtin:${imported}${specifier.type === 'ImportSpecifier' ? `.${specifier.imported.name ?? specifier.imported.value}` : ''}`;
    }
    if (definition.type !== 'Variable') return null;
    const base = capability(definition.node.init, seen);
    if (definition.node.id.type === 'ObjectPattern') {
      const part = definition.node.id.properties.find(item => item.type === 'Property' && item.value === definition.name);
      const name = part && (part.computed ? literal(part.key, source) : part.key.name ?? part.key.value);
      return base && name ? `${base}.${name}` : null;
    }
    return base;
  }
  return capability;
}

export const moduleBoundaries = {
  meta: {
    type: 'problem', schema: [],
    messages: {
      core: 'Pure core cannot depend on other modules or perform I/O.',
      network: 'Network APIs belong in the node adapters.',
      sql: 'SQL APIs and statement text belong in persistence.',
      output: 'Console, stdout and stderr belong in output.',
      child: 'Child processes are forbidden in source modules.',
      adapter: 'Adapter dependencies must use the core ports.',
      clock: 'Use an injected clock and randomness in this module.',
      write: 'File write APIs belong in persistence or output.',
      loading: 'Use literal ESM import specifiers; require, createRequire and computed loading are forbidden.',
    },
  },
  create(context) {
    const source = context.sourceCode;
    const filename = resolve(context.filename);
    const path = relative(context.cwd, filename).replace(/\\/g, '/');
    const area = /^src\/([^/]+)\//.exec(path)?.[1];
    if (!area) return {};
    const adapter = ['node-lnd', 'node-cln'].includes(area);
    const pureTime = ['planner', 'policy', 'ledger', 'approval'].includes(area);
    const writesAllowed = ['persistence', 'output'].includes(area);
    const capability = capabilities(source);
    const reported = new WeakMap();
    function report(node, messageId) {
      const messages = reported.get(node) ?? new Set();
      if (messages.has(messageId)) return;
      messages.add(messageId); reported.set(node, messages);
      context.report({ node, messageId });
    }
    function importSource(node, specifier) {
      // A data: URL is module source text, i.e. computed code.
      if (/^data:/i.test(specifier)) { report(node, 'loading'); return; }
      const name = specifier.replace(/^node:/, '');
      if (builtin(name)) {
        if (area === 'core' && name !== 'crypto') report(node, 'core');
        if (networkBuiltin(name) && !adapter) report(node, 'network');
        if (name === 'sqlite' && area !== 'persistence') report(node, 'sql');
        if (name === 'child_process' && path !== childProcessHost) report(node, 'child');
        if (['module', 'vm', 'repl', 'inspector', 'wasi'].includes(name)) report(node, 'loading');
        return;
      }
      const target = specifier.startsWith('.') || specifier.startsWith('/')
        ? relative(context.cwd, resolve(dirname(filename), specifier)).replace(/\\/g, '/') : specifier;
      const targetArea = /^src\/([^/]+)\//.exec(target)?.[1];
      if (area === 'core' && targetArea !== 'core') report(node, 'core');
      if (adapter && targetArea !== area && targetArea !== 'core') report(node, 'adapter');
      if (['executor', 'reconciler'].includes(area) && ['node-lnd', 'node-cln'].includes(targetArea)) report(node, 'adapter');
    }
    // Calling a value's constructor property ((() => {}).constructor) reaches Function.
    function constructorCall(node) {
      if (node.callee.type === 'MemberExpression' && property(node.callee, source) === 'constructor') report(node, 'loading');
    }
    function inspect(node) {
      const name = capability(node);
      if (!name) return;
      const global = name.replace(/^(?:globalThis|global|window|self)\./, '');
      if (!adapter && ['fetch', 'WebSocket'].includes(global)) report(node, 'network');
      if (area !== 'output' && /^(?:(?:builtin:)?process\.(?:stdout|stderr)|(?:builtin:)?console\.)/.test(global)) report(node, 'output');
      if (pureTime && ['Date.now', 'Math.random'].includes(global)) report(node, 'clock');
      if (/^(?:require|eval|Function|builtin:module\.createRequire)$/.test(global)) report(node, 'loading');
      if (/^(?:builtin:)?process\.(?:mainModule|binding|_linkedBinding|dlopen)(?:\.|$)/.test(global)) report(node, 'loading');
      const fileApi = /^builtin:fs(?:\/promises)?(?:\.promises)?\.(.+)$/.exec(name)?.[1];
      if (fileApi && fileWrites.test(fileApi) && !writesAllowed) report(node, 'write');
      if (area === 'core' && /^(?:builtin:(?:fs|process|console)|process|console)(?:\.|$)/.test(global)) report(node, 'core');
      if (/^builtin:child_process(?:\.|$)/.test(name) && path !== childProcessHost) report(node, 'child');
      if (/^builtin:sqlite(?:\.|$)/.test(name) && area !== 'persistence') report(node, 'sql');
    }
    return {
      ImportDeclaration(node) { importSource(node, node.source.value); },
      ExportNamedDeclaration(node) { if (node.source) importSource(node, node.source.value); },
      ExportAllDeclaration(node) { importSource(node, node.source.value); },
      ImportExpression(node) {
        if (node.source.type !== 'Literal' || typeof node.source.value !== 'string') report(node, 'loading');
        else importSource(node, node.source.value);
      },
      Identifier(node) {
        // Scope references distinguish real API access from keys, declarations and imports.
        if (source.getScope(node).references.some(reference => reference.identifier === node)) inspect(node);
      },
      MemberExpression: inspect,
      CallExpression(node) {
        const name = capability(node.callee)?.replace(/^(?:globalThis|global)\./, '');
        // process.getBuiltinModule loads a builtin without an import declaration.
        if (name && /^(?:builtin:)?process\.getBuiltinModule$/.test(name)) {
          const specifier = literal(node.arguments[0], source);
          if (specifier === null) report(node, 'loading');
          else importSource(node, specifier);
        }
        constructorCall(node);
      },
      NewExpression(node) {
        const name = capability(node.callee)?.replace(/^(?:globalThis|global)\./, '');
        if (pureTime && name === 'Date' && node.arguments.length === 0) report(node, 'clock');
        // A worker given a data: URL or source text with eval: true is computed code loading.
        const script = node.arguments[0]?.type === 'NewExpression' ? node.arguments[0].arguments[0] : node.arguments[0];
        if (name === 'builtin:worker_threads.Worker' && /^data:/i.test(literal(script, source) ?? '')) report(node, 'loading');
        if (name === 'builtin:worker_threads.Worker' && node.arguments[1]?.type === 'ObjectExpression' &&
            node.arguments[1].properties.some(item => item.type === 'SpreadElement' || (item.computed ? literal(item.key, source) : item.key.name ?? item.key.value) === 'eval' &&
              !(item.value.type === 'Literal' && item.value.value === false))) report(node, 'loading');
        constructorCall(node);
      },
      Literal(node) {
        if (area !== 'persistence' && typeof node.value === 'string' && sql.test(node.value)) report(node, 'sql');
      },
      TemplateLiteral(node) {
        if (area !== 'persistence' && sql.test(node.quasis.map(part => part.value.cooked ?? '').join(' '))) report(node, 'sql');
      },
      BinaryExpression(node) {
        // Statement text split into constant pieces is still statement text.
        if (area === 'persistence' || (node.parent.type === 'BinaryExpression' && literal(node.parent, source) !== null)) return;
        const text = literal(node, source);
        if (text !== null && sql.test(text)) report(node, 'sql');
      },
    };
  },
};

export const shellExecution = {
  meta: { type: 'problem', schema: [], messages: { execution: 'Shell execution is forbidden; use a child process argument array.', arguments: 'Child process tooling requires an explicit argument array.' } },
  create(context) {
    const capability = capabilities(context.sourceCode);
    const filename = relative(context.cwd, context.filename).replace(/\\/g, '/');
    return {
      Property(node) {
        const key = node.computed ? literal(node.key) : node.key.name ?? node.key.value;
        if (key === 'shell' && !(node.value.type === 'Literal' && node.value.value === false)) context.report({ node, messageId: 'execution' });
      },
      CallExpression(node) {
        const api = capability(node.callee);
        if (!api?.startsWith('builtin:child_process.')) return;
        if (!/^(?:scripts\/|labs\/docker\/|test\/)/.test(filename) && filename !== childProcessHost) {
          context.report({ node, messageId: 'execution' }); return;
        }
        if (api.endsWith('.exec') || api.endsWith('.execSync') ||
            (/\.(?:spawn|spawnSync|execFile|execFileSync)$/.test(api) &&
             !['ArrayExpression', 'Identifier'].includes(node.arguments[1]?.type))) context.report({ node, messageId: 'arguments' });
      },
    };
  },
};

// All supported source suffixes share one boundary policy.
export const sourceFiles = ['src/**/*.{ts,mts,cts,js,mjs,cjs,tsx,jsx}'];
