import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Field, Poseidon } from 'o1js';

// Vector hex is the little-endian byte encoding of a field element.
const fromHex = (hex) =>
  Field(BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex')));

const file = new URL('../../vectors/poseidon-kimchi.json', import.meta.url);
const { test_vectors: vectors } = JSON.parse(readFileSync(file, 'utf8'));

test('reproduces every shared vector', () => {
  assert.ok(vectors.length > 0, 'zero vector cases ran');
  vectors.forEach((v, i) => {
    const got = Poseidon.hash(v.input.map(fromHex));
    assert.equal(got.toString(), fromHex(v.output).toString(), `vector ${i}`);
  });
  console.log(`vector cases run: ${vectors.length}`);
});
