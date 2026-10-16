import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { Field, Poseidon } from 'o1js';

// Vector hex is the little-endian byte encoding of a field element.
const fromHex = (hex: string) =>
  Field(BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex')));

const { test_vectors: vectors } = JSON.parse(
  readFileSync(new URL('../../vectors/poseidon-kimchi.json', import.meta.url), 'utf8')
) as { test_vectors: { input: string[]; output: string }[] };

it('reproduces every shared Poseidon vector', () => {
  expect(vectors.length, 'zero vector cases ran').toBeGreaterThan(0);
  vectors.forEach((v, i) => {
    const got = Poseidon.hash(v.input.map(fromHex));
    expect(got.toString(), `vector ${i}`).toBe(fromHex(v.output).toString());
  });
  console.log(`vector cases run: ${vectors.length}`);
});
