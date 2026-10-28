// `npm run test:lightnet`: the tests that need the proofs-on lightnet (`lightnet/lightnet.sh up`).
// Proving and block inclusion take minutes, so the timeouts are long and the tests run one at a time.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.lightnet.ts'],
    testTimeout: 30 * 60_000,
    hookTimeout: 30 * 60_000,
    fileParallelism: false,
  },
});
