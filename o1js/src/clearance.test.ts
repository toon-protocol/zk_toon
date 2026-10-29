import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Bool, Field, PrivateKey, Provable, PublicKey, Signature } from 'o1js';
import { clearanceFields, signClearance, verifyClearance, type ClearanceMessage } from './clearance.js';
import { stateFields } from './state.js';
import { tagToBigint } from './primitives.js';

const file = JSON.parse(readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8'));

const stateKey = PrivateKey.fromBigInt(1n);
const msg = (over: Partial<ClearanceMessage> = {}): ClearanceMessage => ({
  stateKey: stateKey.toPublicKey(),
  nullifier: Field(42),
  destination: PrivateKey.fromBigInt(7n).toPublicKey(),
  ...over,
});

// Every input a circuit variable, as the vault checks it.
const inCircuit = async (sig: Signature, m: ClearanceMessage) => {
  let ok = false;
  await Provable.runAndCheck(() => {
    const s = Provable.witness(Signature, () => sig);
    const k = Provable.witness(PublicKey, () => m.stateKey);
    const n = Provable.witness(Field, () => m.nullifier);
    const d = Provable.witness(PublicKey, () => m.destination);
    const r = verifyClearance(s, { stateKey: k, nullifier: n, destination: d });
    Provable.asProver(() => {
      ok = r.toBoolean();
    });
  });
  return ok;
};

describe('clearance', () => {
  it('is six fields led by the tag of toon.zk.clearance.v1', () => {
    const m = msg();
    expect(clearanceFields(m).map(String)).toEqual([
      tagToBigint('toon.zk.clearance.v1').toString(),
      m.stateKey.x.toString(), m.stateKey.isOdd.toField().toString(),
      '42',
      m.destination.x.toString(), m.destination.isOdd.toField().toString(),
    ]);
  });

  it('verifies inside a circuit when signed by the state key', async () => {
    expect(await inCircuit(signClearance(stateKey, msg()), msg())).toBe(true);
  });

  it('is refused over another nullifier, another destination, or signed by another key', async () => {
    const sig = signClearance(stateKey, msg());
    expect(await inCircuit(sig, msg({ nullifier: Field(43) }))).toBe(false);
    expect(await inCircuit(sig, msg({ destination: PrivateKey.fromBigInt(8n).toPublicKey() }))).toBe(false);
    expect(await inCircuit(Signature.create(PrivateKey.fromBigInt(2n), clearanceFields(msg())), msg())).toBe(false);
  });

  it('is not passed by a state signature', async () => {
    const m = msg();
    const stateSig = Signature.create(
      stateKey, stateFields({ vault: m.stateKey, commitment: m.destination.toGroup(), anchor: m.nullifier })
    );
    expect(await inCircuit(stateSig, m)).toBe(false);
  });
});

describe('clearance vectors', () => {
  const message = (c: any): ClearanceMessage => ({
    stateKey: PrivateKey.fromBigInt(BigInt(c.stateSecret)).toPublicKey(),
    nullifier: Field(c.nullifier),
    destination: PublicKey.from({ x: Field(c.destination.x), isOdd: Bool(c.destination.isOdd === '1') }),
  });
  const sig = (c: any) => Signature.fromJSON({ r: c.signature.r, s: c.signature.s });

  it('are reproduced, signed under the devnet ID, and verify inside a circuit', async () => {
    expect(file.clearances.networkId).toBe('devnet');
    const cases = file.clearances.cases;
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(clearanceFields(message(c)).map(String)).toEqual(c.fields);
      const signed = signClearance(PrivateKey.fromBigInt(BigInt(c.stateSecret)), message(c));
      expect({ r: signed.r.toString(), s: signed.s.toBigInt().toString() }).toEqual(c.signature);
      expect(await inCircuit(sig(c), message(c))).toBe(true);
    }
    console.log(`vector cases run: ${cases.length}`);
  });

  it('each cover one nullifier, one destination and one key', async () => {
    const [a, otherNullifier, otherDestination, otherKey] = file.clearances.cases;
    expect(await inCircuit(sig(a), { ...message(a), nullifier: Field(otherNullifier.nullifier) })).toBe(false);
    expect(await inCircuit(sig(a), { ...message(a), destination: message(otherDestination).destination })).toBe(false);
    expect(await inCircuit(sig(a), { ...message(a), stateKey: message(otherKey).stateKey })).toBe(false);
  });

  it('are refused when signed under the mainnet ID', async () => {
    const c = file.clearances.mainnetClearance;
    expect(c.networkId).toBe('mainnet');
    expect(await inCircuit(sig(c), message(c))).toBe(false);
  });
});
