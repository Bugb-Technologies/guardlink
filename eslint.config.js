/**
 * GuardLink — ESLint flat config.
 *
 * `npm run lint` has never worked. The earlier diagnosis ("ESLint v9 rejects
 * .eslintrc") was wrong: there was no `.eslintrc*`, no `eslint.config.*`, and
 * eslint was not installed. The script pointed at nothing.
 *
 * The rule set is deliberately the one that PASSES today at error level. A
 * config that fails on hundreds of pre-existing violations gets `|| true`'d
 * within a week, and then the repo has a lint script that lies instead of one
 * that does nothing — strictly worse. Measured on this codebase at
 * `typescript-eslint/recommended`:
 *
 *   156  @typescript-eslint/no-explicit-any
 *    82  @typescript-eslint/no-unused-vars
 *     8  prefer-const
 *   ---
 *   246  errors
 *
 * What each of those became, and why:
 *
 * - `no-explicit-any` — OFF. 156 sites. Typing them is a real project with real
 *   value, and it is not a defect sweep. Turning this on today would mean 156
 *   `any` casts becoming 156 `eslint-disable` comments, which buys nothing.
 *
 * - `no-unused-vars` — WARN, at 73 after the ignore patterns below. Mostly dead
 *   imports across 26 files. Mechanical and safe to clean (tsc catches any
 *   mistake immediately), but a 26-file cleanup does not belong in the same
 *   branch as the defect fixes it would be reviewed alongside. Visible as
 *   warnings so the debt is counted rather than hidden; promote to `error` once
 *   the cleanup lands.
 *
 * - `no-useless-escape` — OFF. All 13 sites are inside the parser's regexes.
 *   "Useless" escapes there are often deliberate — `\.` reads as a literal dot
 *   whether or not the character class makes it redundant — and editing a
 *   parser's regexes to satisfy a linter is how a parser breaks silently. This
 *   is the same repo where a grammar defect (D19) shipped for a full epic.
 *
 * - `prefer-const` — ERROR, with `destructuring: 'all'`. Four sites are
 *   `let { model, diagnostics } = await parseProject(…)` where `model` is
 *   reassigned and `diagnostics` is not. Splitting the destructure to satisfy
 *   the linter would be worse code; `destructuring: 'all'` is the setting for
 *   exactly this pattern, not an exemption for it.
 *
 * - `no-empty` — ERROR, with `allowEmptyCatch`. The codebase uses `catch {}`
 *   deliberately for best-effort work (agent-file sync after a review write).
 *
 * Everything else in `js.configs.recommended` and `typescript-eslint`'s
 * recommended set is on at error and passes at zero.
 */

import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      // Generated or illustrative, not authored: GuardLink's own artifacts and
      // the worked examples shipped for documentation.
      '.guardlink/**',
      'docs/**',
      'examples/**',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        // `const { generated_at, ...durable } = model` is how volatile fields
        // are dropped at every emission boundary in this codebase. That is the
        // idiom, not an oversight.
        ignoreRestSiblings: true,
        caughtErrors: 'none',
      }],
      'no-useless-escape': 'off',
      'no-empty': ['error', { allowEmptyCatch: true }],
      'prefer-const': ['error', { destructuring: 'all' }],
      'eqeqeq': ['error', 'smart'],
      'no-var': 'error',
    },
  },
);
