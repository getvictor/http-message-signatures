import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Base recommended rules
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,

  // Project-specific configuration
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // Files to lint
  {
    files: ['**/*.ts'],
  },

  // Ignore patterns
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      '**/*.js',
      '**/*.d.ts',
      '**/*.spec.ts',
    ],
  },

  // Custom rules for demo project
  {
    rules: {
      // Turn off any type checks - acceptable in demo code with crypto APIs
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/restrict-template-expressions': 'off',

      // Allow namespaces for Express type augmentation
      '@typescript-eslint/no-namespace': 'off',

      // Allow async functions without await (needed for library interfaces)
      '@typescript-eslint/require-await': 'off',

      // Keep important rules as errors
      '@typescript-eslint/no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
      '@typescript-eslint/no-floating-promises': 'error',
    },
  }
);
