// The committed request-proof fixtures (#65) carry the key `RequestProgram` compiles to at this commit.
// The proofs are randomised and are not rebuilt here; Rust verifies them (`zk-prover/tests/request_proofs.rs`).
import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { VerificationKey } from 'o1js';
import type { RequestFixtures } from './request-fixtures.js';
import { RequestProgram } from './request.js';

const fixtures: RequestFixtures = JSON.parse(
  readFileSync(new URL('../../test-vectors/request-proofs/request-proofs.json', import.meta.url), 'utf8'),
);

describe('the committed request-proof fixtures', () => {
  let compiled: VerificationKey;
  beforeAll(async () => {
    ({ verificationKey: compiled } = await RequestProgram.compile());
  }, 900_000);

  it('carry the key RequestProgram compiles to; regenerate with `npm run request-fixtures` if this fails', () => {
    expect(fixtures.verificationKey.hash).toBe(compiled.hash.toString());
    expect(fixtures.verificationKey.data).toBe(compiled.data);
  });
});
