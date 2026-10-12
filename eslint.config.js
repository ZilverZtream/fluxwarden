import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Strict type checks apply to TypeScript; file-specific overrides cover test readers and scripts.
export default defineConfig(
  { ignores: ['dist/**', 'node_modules/**', '.ratchet/**', 'labs/.runtime/**'] },
  js.configs.recommended,
  tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: {
        projectService: {
          // Files outside tsconfig.json's `include` (tests, configuration) get type information
          // from a default project with the same compiler options.
          allowDefaultProject: ['test/*/*.ts', 'vitest.config.ts'],
          defaultProject: 'tsconfig.json',
        },
        tsconfigRootDir: dirname(fileURLToPath(import.meta.url)),
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
  // The test YAML and JSON readers stringify parsed values of a union type on purpose.
  { files: ['test/**/*.ts'], rules: { '@typescript-eslint/no-base-to-string': 'off' } },
  { files: ['**/*.js', '**/*.mjs'], ...tseslint.configs.disableTypeChecked },
);
