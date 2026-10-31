// The wrap proofs zk-prover makes in Rust (`fixture-gen/regenerate.sh --write` writes
// `rust_<method>_proof.json`) verify in o1js under the verification key o1js compiled for the
// program with the methods `land` and `setup`. A changed proof or public input is refused.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { verify, type JsonProof } from 'o1js';

const fixture = (name: string) =>
  JSON.parse(gunzipSync(readFileSync(new URL(`../../zk-prover/fixtures/${name}.gz`, import.meta.url))).toString());

const vk: string = fixture('inputs.json').vk;

type Saved = { proof: string; publicInputFields: string[]; publicOutputFields: string[] };
const jsonProof = (f: Saved, over: Partial<JsonProof> = {}): JsonProof => ({
  publicInput: f.publicInputFields,
  publicOutput: f.publicOutputFields,
  maxProofsVerified: 0,
  proof: f.proof,
  ...over,
});

describe('the Rust wrap proof under the program verification key', () => {
  for (const method of ['land', 'setup']) {
    it(`${method}: o1js verifies it, and refuses a changed proof or public input`, async () => {
      const rust: Saved = fixture(`rust_${method}_proof.json`);
      expect(await verify(jsonProof(rust), vk)).toBe(true);

      const input = [...rust.publicInputFields];
      input[0] = (BigInt(input[0]) + 1n).toString();
      expect(await verify(jsonProof(rust, { publicInput: input }), vk)).toBe(false);

      // Flip one hex digit of the first wrap challenge, `alpha`: it still parses.
      const sexp = Buffer.from(rust.proof, 'base64url').toString();
      const at = sexp.indexOf('(alpha((inner(') + '(alpha((inner('.length + 15;
      const flipped = sexp.slice(0, at) + (parseInt(sexp[at], 16) ^ 1).toString(16) + sexp.slice(at + 1);
      const tampered = Buffer.from(flipped).toString('base64').replace(/\+/g, '-').replace(/\//g, '_'); // padded, as o1js writes it
      expect(tampered).not.toBe(rust.proof);
      expect(await verify(jsonProof(rust, { proof: tampered }), vk)).toBe(false);
    });
  }
});
