import { defineConfig } from 'vitest/config';

// The code graph is optional input that GuardLink discovers on PATH. Off for the
// whole suite, so no answer here depends on graph tooling or graphs installed on
// the machine running it; tests/codegraph.test.ts pins its transports explicitly.
export default defineConfig({
  test: {
    env: { GUARDLINK_CODEGRAPH: 'off' },
  },
});
