// The wrap proofs zk-prover makes in Rust (`fixture-gen/regenerate.sh --write` writes
// `rust_<method>_proof.json`, `--vault` the vault's `rust_vault_<case>_proof.json`) verify in o1js under the verification key o1js compiled for the
// program with the methods `land` and `setup`, and for the toy zkApp (`fixture-gen/toy.mjs`), whose
// methods verify no proof and one proof, and for the real vault, each of whose methods (and `reduce` from a
// real chunk) is wrapped from o1js's step proof. A changed proof or public input is refused.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { verify, type JsonProof } from 'o1js';

const fixture = (name: string) =>
  JSON.parse(gunzipSync(readFileSync(new URL(`../../zk-prover/fixtures/${name}.gz`, import.meta.url))).toString());

const vk: string = fixture('inputs.json').vk;
const toyVk: string = fixture('toy_inputs.json').vk;
const vaultVk: string = fixture('vault_keys.json').vault.data;
const VAULT_CASES = [
  'setup', 'deposit', 'mutualClose', 'escape', 'finalize', 'defeat', 'raise', 'sweepExpired', 'reduce', 'reduce_recursive',
];

type Saved = { proof: string; publicInputFields: string[]; publicOutputFields: string[]; maxProofsVerified?: number };
const jsonProof = (f: Saved, over: Partial<JsonProof> = {}): JsonProof => ({
  publicInput: f.publicInputFields,
  publicOutput: f.publicOutputFields,
  maxProofsVerified: (f.maxProofsVerified ?? 0) as 0 | 1 | 2,
  proof: f.proof,
  ...over,
});

describe('the Rust wrap proof under the program verification key', () => {
  // `rust_witness_land`: `land` wholly in Rust, the step witness too (#36). `toy_plain` and `toy_recurse`:
  // the methods of the toy zkApp, whose program verifies at most one proof.
  for (const [name, key] of [
    ['land', vk],
    ['setup', vk],
    ['witness_land', vk],
    ['toy_plain', toyVk],
    ['toy_recurse', toyVk],
    ...VAULT_CASES.map((c) => [`vault_${c}`, vaultVk]),
  ]) {
    it(`${name}: o1js verifies it, and refuses a changed proof or public input`, async () => {
      const rust: Saved = fixture(`rust_${name}_proof.json`);
      expect(await verify(jsonProof(rust), key)).toBe(true);

      const input = [...rust.publicInputFields];
      input[0] = (BigInt(input[0]) + 1n).toString();
      expect(await verify(jsonProof(rust, { publicInput: input }), key)).toBe(false);

      // Flip one hex digit of the first wrap challenge, `alpha`: it still parses.
      const sexp = Buffer.from(rust.proof, 'base64url').toString();
      const at = sexp.indexOf('(alpha((inner(') + '(alpha((inner('.length + 15;
      const flipped = sexp.slice(0, at) + (parseInt(sexp[at], 16) ^ 1).toString(16) + sexp.slice(at + 1);
      const tampered = Buffer.from(flipped).toString('base64').replace(/\+/g, '-').replace(/\//g, '_'); // padded, as o1js writes it
      expect(tampered).not.toBe(rust.proof);
      expect(await verify(jsonProof(rust, { proof: tampered }), key)).toBe(false);
    });
  }
});
