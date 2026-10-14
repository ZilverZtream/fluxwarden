import { builtinModules } from 'node:module';
import { dirname, posix } from 'node:path';
import ts from 'typescript';

export interface BoundaryViolation { boundary: string; line: number }
const networks = new Set(['http', 'https', 'http2', 'net', 'tls', 'dgram']);
const network = (module: string): boolean => networks.has(module) || /^_(?:http|tls|stream_wrap)/.test(module);
const loaders = new Set(['module', 'vm', 'repl', 'inspector', 'wasi']);
const statement = /\b(?:SELECT\s+.+?\s+FROM|INSERT\s+(?:OR\s+\w+\s+)?INTO|REPLACE\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE)\b/is;
// Constant string text of a literal or of literals joined with "+"; undefined otherwise.
function constantText(node: ts.Node): string | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isParenthesizedExpression(node)) return constantText(node.expression);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = constantText(node.left), right = constantText(node.right);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  return undefined;
}
const writers = /^(?:write|append|createWriteStream|truncate|rename|unlink|rm|mkdir|rmdir|copyFile|cp|link|symlink|chmod|chown)/;
const builtins = new Set(builtinModules.map(name => name.replace(/^node:/, '')));
const memberName = (node: ts.Node): string | undefined => ts.isPropertyAccessExpression(node) ? node.name.text :
  ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression) ? node.argumentExpression.text : undefined;

// A separate TypeScript parse supplies the second boundary verdict; no lint configuration is read.
export function checkBoundaries(path: string, source: string): BoundaryViolation[] {
  const result = checkBoundarySources([{ path, source }]).get(path);
  if (!result) throw new Error('source has no boundary verdict');
  return result;
}

export function checkBoundarySources(sources: readonly { path: string; source: string }[]): Map<string, BoundaryViolation[]> {
  const files = new Map(sources.map(({ path, source }) => [path.replace(/\\/g, '/'), ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true)]));
  if (files.size !== sources.length) throw new Error('source inventory contains duplicate paths');
  const options: ts.CompilerOptions = { noLib: true, noResolve: true };
  const host = ts.createCompilerHost(options);
  host.getSourceFile = name => files.get(name.replace(/\\/g, '/'));
  host.fileExists = name => files.has(name.replace(/\\/g, '/'));
  host.readFile = name => files.get(name.replace(/\\/g, '/'))?.text;
  const symbols = ts.createProgram([...files.keys()], options, host).getTypeChecker();
  return new Map(sources.map(({ path }) => {
    const file = files.get(path.replace(/\\/g, '/'));
    if (!file) throw new Error('source inventory has no parsed file');
    return [path, checkSourceBoundaries(path, file, symbols)];
  }));
}

function checkSourceBoundaries(path: string, file: ts.SourceFile, symbols: ts.TypeChecker): BoundaryViolation[] {
  const normalized = path.replace(/\\/g, '/');
  if (!normalized.startsWith('src/')) return [];
  const area = normalized.split('/')[1];
  const adapter = area === 'node-lnd' || area === 'node-cln';
  // A declaration in another script cannot exempt this file's use of a global API.
  const globalIdentifier = (node: ts.Node, name: string): boolean => ts.isIdentifier(node) && node.text === name &&
    !symbols.getSymbolAtLocation(node)?.getDeclarations()?.some(declaration => declaration.getSourceFile() === file);
  const violations: BoundaryViolation[] = [];
  const bindings = new Map<string, { module: string; name?: string }>();
  const add = (boundary: string, node: ts.Node): void => {
    violations.push({ boundary, line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1 });
  };
  function specifier(value: string, node: ts.Node): void {
    const module = value.replace(/^node:/, '');
    const target = value.startsWith('.') ? posix.normalize(posix.join(dirname(normalized), value)) : value;
    const targetArea = target.startsWith('src/') ? target.split('/')[1] : undefined;
    // A data: specifier carries the module source text itself.
    if (value.startsWith('data:')) add('module loading', node);
    if (area === 'core' && ((targetArea !== undefined && targetArea !== 'core') || (builtins.has(module) && module !== 'crypto') || (!value.startsWith('.') && !builtins.has(module)))) add('pure core', node);
    if (network(module) && !adapter) add('network', node);
    if (loaders.has(module)) add('module loading', node);
    if (module === 'sqlite' && area !== 'persistence') add('SQL', node);
    // The single exemption: the Windows owner-only file helper runs icacls and whoami by absolute path.
    if (module === 'child_process' && normalized !== 'src/platform/owner-only.ts') add('child process', node);
    if ((area === 'executor' || area === 'reconciler') && (targetArea === 'node-lnd' || targetArea === 'node-cln')) add('adapter dependency', node);
    if (adapter && targetArea !== undefined && targetArea !== area && targetArea !== 'core') add('adapter dependency', node);
  }
  function visit(node: ts.Node): void {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      const module = node.moduleSpecifier.text;
      specifier(module, node);
      if (ts.isImportDeclaration(node)) {
        const named = node.importClause?.namedBindings;
        if (named && ts.isNamespaceImport(named)) bindings.set(named.name.text, { module });
        if (named && ts.isNamedImports(named)) for (const item of named.elements) bindings.set(item.name.text, { module, name: item.propertyName?.text ?? item.name.text });
        if (node.importClause?.name) bindings.set(node.importClause.name.text, { module });
      }
    }
    if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        if (!arg || !ts.isStringLiteral(arg)) add('literal import', node);
        else specifier(arg.text, node);
      }
      if (ts.isIdentifier(node.expression) && ['require', 'eval', 'Function'].includes(node.expression.text)) add('module loading', node);
      // process.getBuiltinModule loads a builtin by name, exactly like an import of it.
      if ((ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)) && globalIdentifier(node.expression.expression, 'process') && memberName(node.expression) === 'getBuiltinModule') {
        const arg = node.arguments[0];
        if (!arg || !ts.isStringLiteral(arg)) add('literal import', node);
        else specifier(arg.text, node);
      }
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') add('module loading', node);
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      const binding = bindings.get(node.expression.text);
      const options = node.arguments?.[1];
      if (binding?.module.replace(/^node:/, '') === 'worker_threads' && binding.name === 'Worker') {
        const script = node.arguments?.[0];
        // new Worker(new URL('data:...')) runs source text carried in the URL.
        if (script !== undefined && ts.isNewExpression(script) && ts.isIdentifier(script.expression) && script.expression.text === 'URL' &&
            script.arguments?.[0] !== undefined && ts.isStringLiteral(script.arguments[0]) && script.arguments[0].text.startsWith('data:')) add('module loading', node);
        // Options that set eval to anything but false, or that may through a spread, evaluate source text.
        if (options !== undefined && ts.isObjectLiteralExpression(options) && options.properties.some(item => ts.isSpreadAssignment(item) ||
            (ts.isPropertyAssignment(item) && (ts.isIdentifier(item.name) || ts.isStringLiteral(item.name)) && item.name.text === 'eval' && item.initializer.kind !== ts.SyntaxKind.FalseKeyword))) add('module loading', node);
      }
    }
    if (area !== 'persistence' && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isBinaryExpression(node)) && !(ts.isBinaryExpression(node.parent) && constantText(node.parent) !== undefined)) {
      const text = constantText(node);
      if (text !== undefined && statement.test(text)) add('SQL', node);
    }
    if (ts.isIdentifier(node)) {
      const propertyName = (ts.isPropertyAccessExpression(node.parent) && node.parent.name === node) ||
        ((ts.isPropertyAssignment(node.parent) || ts.isMethodDeclaration(node.parent) || ts.isPropertySignature(node.parent)) && node.parent.name === node);
      if (!adapter && !propertyName && ['fetch', 'WebSocket'].includes(node.text) && globalIdentifier(node, node.text)) add('network', node);
      if (area === 'core' && !propertyName && globalIdentifier(node, 'process')) add('pure core', node);
      const binding = bindings.get(node.text);
      if (binding?.module.replace(/^node:/, '').startsWith('fs') && binding.name && writers.test(binding.name) && !['persistence', 'output'].includes(area ?? '')) add('file write', node);
      if (binding?.module === 'node:module' && binding.name === 'createRequire') add('module loading', node);
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = memberName(node);
      const object = ts.isIdentifier(node.expression) ? node.expression.text : undefined;
      if (!adapter && globalIdentifier(node.expression, 'globalThis') && ['fetch', 'WebSocket'].includes(name ?? '')) add('network', node);
      if (area !== 'output' && ((globalIdentifier(node.expression, 'process') && ['stdout', 'stderr'].includes(name ?? '')) || globalIdentifier(node.expression, 'console'))) add('output', node);
      if (['planner', 'policy', 'ledger', 'approval'].includes(area ?? '') && ((globalIdentifier(node.expression, 'Date') && name === 'now') || (globalIdentifier(node.expression, 'Math') && name === 'random'))) add('injected clock', node);
      const binding = object ? bindings.get(object) : undefined;
      if (binding?.module.replace(/^node:/, '').startsWith('fs') && name && writers.test(name) && !['persistence', 'output'].includes(area ?? '')) add('file write', node);
      if (name === 'createRequire' && binding?.module === 'node:module') add('module loading', node);
      if (globalIdentifier(node.expression, 'process') && ['binding', '_linkedBinding', 'dlopen', 'mainModule'].includes(name ?? '')) add('module loading', node);
    }
    if (['planner', 'policy', 'ledger', 'approval'].includes(area ?? '') && ts.isNewExpression(node) && globalIdentifier(node.expression, 'Date') && (node.arguments?.length ?? 0) === 0) add('injected clock', node);
    ts.forEachChild(node, visit);
  }
  visit(file);
  return violations;
}
