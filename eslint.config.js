import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { childProcessHost, moduleBoundaries, shellExecution, sourceFiles } from './scripts/boundary-rules.mjs';
import { credentialCapability } from './scripts/credential-rules.mjs';

const sourceImports = [
  { regex: '^(?:node:)?child_process$', message: 'Child processes are forbidden in source modules.' },
  { regex: '(?:^|/)approval/verified(?:\\.js)?$', importNames: ['sealVerified'], message: 'Only approval verification may mark an approval as verified.' },
];
const networkImports = { regex: '^(?:node:)?(?:http|https|http2|net|tls|dgram)$', message: 'Network modules belong in the node adapters.' };
const sqlImports = { regex: '^(?:node:)?sqlite$', message: 'SQL modules belong in persistence.' };
function importRestrictions(patterns) {
  return ['error', { patterns: [...sourceImports, ...patterns] }];
}

const repositoryRoot = dirname(fileURLToPath(import.meta.url));
// Directories excluded from version control are not linted either.
const ignoredDirectories = readFileSync(`${repositoryRoot}/.gitignore`, 'utf8').split(/\r?\n/)
  .map(line => line.trim()).filter(line => line.endsWith('/') && !line.startsWith('#') && !line.startsWith('!'))
  .map(line => `${line.replace(/^\//, '')}**`);


// Amounts retain bigint precision even when intermediate products exceed the number range.
const amountConversions = {
  meta: { type: 'problem', schema: [], messages: { conversion: 'Keep monetary values as bigint; format them as decimal strings.' } },
  create(context) {
    const services = context.sourceCode.parserServices;
    const checker = services.program?.getTypeChecker();
    function monetary(node) {
      if (!node || typeof node !== 'object') return false;
      if (node.type === 'Identifier' && /msat|sat(?:s|oshis?)?(?![a-z])|amount|principal|fee|balance|reserve|spendable|receivable/i.test(node.name)) return true;
      const typed = services.esTreeNodeToTSNodeMap?.get(node);
      if (checker && typed && /\bMsat\b|\b__msat\b/.test(checker.typeToString(checker.getTypeAtLocation(typed)))) return true;
      return Object.entries(node).some(([key, value]) => key !== 'parent' &&
        (Array.isArray(value) ? value.some(monetary) : value && typeof value === 'object' && 'type' in value && monetary(value)));
    }
    return {
      CallExpression(node) {
        const callee = node.callee;
        const direct = callee.type === 'Identifier' && ['Number', 'parseInt', 'parseFloat'].includes(callee.name);
        const member = callee.type === 'MemberExpression' && callee.object.type === 'Identifier' &&
          (callee.object.name === 'Math' || (['Number', 'globalThis'].includes(callee.object.name) &&
            ['Number', 'parseInt', 'parseFloat'].includes(callee.property.name ?? callee.property.value)));
        if ((direct || member) && node.arguments.some(monetary)) context.report({ node, messageId: 'conversion' });
      },
      UnaryExpression(node) {
        if (node.operator === '+' && monetary(node.argument)) context.report({ node, messageId: 'conversion' });
      },
      NewExpression(node) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'Number' && node.arguments.some(monetary)) context.report({ node, messageId: 'conversion' });
      },
    };
  },
};

// Strict type checks apply to TypeScript; file-specific overrides cover test readers and scripts.
export default defineConfig(
  { ignores: ignoredDirectories },
  js.configs.recommended,
  tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: {
        projectService: {
          allowDefaultProject: [],
          defaultProject: 'tsconfig.json',
        },
        tsconfigRootDir: repositoryRoot,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-declaration-merging': 'error',
      '@typescript-eslint/no-unsafe-enum-comparison': 'error',
      '@typescript-eslint/no-unsafe-function-type': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/no-unsafe-unary-minus': 'error',
    },
  },
  {
    files: ['test/**/*.ts', 'vitest*.config.ts', 'labs/scenarios/**/*.d.mts'],
    languageOptions: {
      parserOptions: { projectService: false, project: './tsconfig.tests.json' },
    },
  },
  {
    files: ['src/core/**/*.ts'],
    plugins: { money: { rules: { 'no-number-conversion': amountConversions } } },
    rules: { 'money/no-number-conversion': 'error' },
  },
  { files: sourceFiles, plugins: { credentials: { rules: { 'restricted-capability': credentialCapability } } }, rules: {
      // Exports of adapter and signer modules that reach the reveal capability and can carry
      // text or bytes (in the signer: every export that can), each with the reason it holds no
      // credential: { file: 'src/node-lnd/x.ts', export: 'name', reason: '...' }.
      'credentials/restricted-capability': ['error', { allow: [
        { file: 'src/approval/sign.ts', export: 'createApproval', reason: 'returns the approval token JSON: proposal fields, caps, expiry, nonce, key id and the Ed25519 signature' },
        { file: 'src/approval/sign.ts', export: 'createApprovalFromKeyFile', reason: 'reads the private signing key inside the signer and returns only the signed approval token' },
        { file: 'src/approval/sign.ts', export: 'writePrivateKeyFile', reason: 'returns the write status: written, exists, failed or invalid-path' },
        { file: 'src/node-lnd/rest.ts', export: 'openLndRest', reason: 'returns the REST client: its calls answer node JSON; the macaroon stays in a private Secret field and is revealed only into the request header' },
        { file: 'src/node-cln/rest.ts', export: 'openClnRest', reason: 'returns the REST client: its calls answer node JSON; the rune stays in a private Secret field and is revealed only into the request header' },
      ] }],
    },
  },
  // The test YAML and JSON readers stringify parsed values of a union type on purpose.
  { files: ['test/**/*.ts'], rules: { '@typescript-eslint/no-base-to-string': 'off' } },
  { files: ['**/*.js', '**/*.mjs'], ...tseslint.configs.disableTypeChecked },
  {
    files: ['**/*.{ts,mts,cts,js,mjs,cjs,tsx,jsx}'],
    plugins: { boundaries: { rules: { modules: moduleBoundaries, 'shell-execution': shellExecution } } },
    rules: { 'boundaries/shell-execution': 'error' },
  },
  { files: sourceFiles, rules: { 'boundaries/modules': 'error' } },
  {
    files: sourceFiles,
    rules: {
      'no-restricted-imports': importRestrictions([]),
      'no-restricted-syntax': ['error', {
        selector: "ImportExpression[source.type!='Literal']",
        message: 'Computed loading is forbidden; use a literal import specifier.',
      }],
    },
  },
  {
    files: sourceFiles, ignores: ['src/node-lnd/**', 'src/node-cln/**', 'src/persistence/**'],
    rules: {
      'no-restricted-imports': importRestrictions([networkImports, sqlImports]),
      'no-restricted-globals': ['error', { name: 'fetch', message: 'Network APIs belong in the node adapters.' }, { name: 'WebSocket', message: 'Network APIs belong in the node adapters.' }],
    },
  },
  { files: ['src/persistence/**/*.{ts,mts,cts,js,mjs,cjs,tsx,jsx}'], rules: { 'no-restricted-imports': importRestrictions([networkImports]), 'no-restricted-globals': ['error', { name: 'fetch', message: 'Network APIs belong in the node adapters.' }, { name: 'WebSocket', message: 'Network APIs belong in the node adapters.' }] } },
  { files: ['src/node-{lnd,cln}/**/*.{ts,mts,cts,js,mjs,cjs,tsx,jsx}'], rules: { 'no-restricted-imports': importRestrictions([sqlImports]) } },
  // The one module that runs icacls.exe and whoami.exe (argument arrays, no shell; boundary-rules.mjs).
  { files: [childProcessHost], rules: { 'no-restricted-imports': ['error', { patterns: [networkImports, sqlImports] }] } },
);
