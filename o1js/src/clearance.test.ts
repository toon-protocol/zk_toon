import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Field, PrivateKey, PublicKey, Signature } from 'o1js';
import { clearanceFields, signClearance, verifyClearance } from './clearance.js';
import { TAGS, tagToBigint } from './primitives.js';
import { stateFields } from './state.js';
import { G } from './balance.js';

const file = JSON.parse(readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8'));
const cases = file.clearances.cases;
const keyOf = (secret: string) => PrivateKey.fromBigInt(BigInt(secret));
const msg = (e: any) => ({
  stateKey: keyOf(e.stateSecret).toPublicKey(), nullifier: Field(e.nullifier),
  destination: PublicKey.from({ x: Field(e.destination.x), isOdd: (e.destination.isOdd === '1') as any }),
});

describe('clearance', () => {
  it('reproduces every vector: fields and signature', () => {
    expect(cases.length).toBeGreaterThan(0);
    for (const e of cases) {
      const m = msg(e);
      expect(clearanceFields(m).map((f) => f.toString())).toEqual(e.fields);
      expect(clearanceFields(m)[0].toBigInt()).toBe(tagToBigint(TAGS.clearance));
      const sig = signClearance(keyOf(e.stateSecret), m);
      expect({ r: sig.r.toString(), s: sig.s.toBigInt().toString() }).toEqual(e.signature);
      expect(verifyClearance(sig, m).toBoolean()).toBe(true);
    }
  });

  it('covers one nullifier and one destination, and one key', () => {
    const [a, otherNullifier, otherDestination, otherKey] = cases;
    const sig = signClearance(keyOf(a.stateSecret), msg(a));
    expect(verifyClearance(sig, { ...msg(a), nullifier: Field(otherNullifier.nullifier) }).toBoolean()).toBe(false);
    expect(verifyClearance(sig, { ...msg(a), destination: msg(otherDestination).destination }).toBoolean()).toBe(false);
    expect(verifyClearance(sig, { ...msg(a), stateKey: msg(otherKey).stateKey }).toBoolean()).toBe(false);
  });

  it('never passes as a state message', () => {
    const m = msg(cases[0]);
    const sig = signClearance(keyOf(cases[0].stateSecret), m);
    // Five-field state messages differ in length and first field from a six-field clearance.
    const state = stateFields({ vault: m.stateKey, commitment: G, anchor: m.nullifier });
    expect(state.length).not.toBe(clearanceFields(m).length);
    expect(sig.verify(m.stateKey, state).toBoolean()).toBe(false);
    expect(Signature.create(keyOf(cases[0].stateSecret), state).verify(m.stateKey, clearanceFields(m)).toBoolean()).toBe(false);
  });
});
