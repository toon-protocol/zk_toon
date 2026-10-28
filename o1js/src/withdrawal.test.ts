import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Bool, Field, PrivateKey, Provable, Signature, verify } from 'o1js';
import { expiryOf } from './policy.js';
import { nullifier } from './primitives.js';
import { RequestProgram } from './request.js';
import { stateFields } from './state.js';
import {
  KIND_ESCAPE, KIND_MUTUAL_CLOSE, KIND_OWNERSHIP, WithdrawalPrivate, WithdrawalProgram, WithdrawalPublic,
  checkWithdrawal,
} from './withdrawal.js';
import {
  WITHDRAWAL_SAMPLES, buildWithdrawal, defaultWithdrawal, withdrawalVector, type WithdrawalOptions,
} from './withdrawal-sample.js';

// Proofs off: the constraints are checked, no proof is made.
const holds = async (kind: number, pub: WithdrawalPublic, priv: WithdrawalPrivate) => {
  try {
    await Provable.runAndCheck(() => {
      checkWithdrawal(kind, Provable.witness(WithdrawalPublic, () => pub), Provable.witness(WithdrawalPrivate, () => priv));
    });
    return true;
  } catch {
    return false;
  }
};
const sample = (kind: number, o: Partial<WithdrawalOptions> = {}) => buildWithdrawal({ ...defaultWithdrawal(kind), ...o });
const withPub = (s: { pub: WithdrawalPublic }, over: Partial<WithdrawalPublic>) => new WithdrawalPublic({ ...s.pub, ...over });
const withPriv = (s: { priv: WithdrawalPrivate }, over: Partial<WithdrawalPrivate>) => new WithdrawalPrivate({ ...s.priv, ...over });

describe('withdrawal constraints', () => {
  it.each([KIND_MUTUAL_CLOSE, KIND_OWNERSHIP])('hold for kind %i on a genesis and on a signed state', async (kind) => {
    for (const signed of [false, true]) {
      const s = sample(kind, { signed });
      expect(await holds(kind, s.pub, s.priv)).toBe(true);
    }
  });

  it('are bound to the method kind', async () => {
    const s = sample(KIND_MUTUAL_CLOSE);
    expect(await holds(KIND_OWNERSHIP, s.pub, s.priv)).toBe(false);
    for (const kind of [0, KIND_ESCAPE, 4]) {
      expect(await holds(KIND_MUTUAL_CLOSE, withPub(s, { kind: Field(kind) }), s.priv)).toBe(false);
    }
  });

  it('require a zero nextNullifier and validUntil', async () => {
    for (const kind of [KIND_MUTUAL_CLOSE, KIND_OWNERSHIP]) {
      const s = sample(kind);
      expect(await holds(kind, withPub(s, { nextNullifier: Field(1) }), s.priv)).toBe(false);
      expect(await holds(kind, withPub(s, { validUntil: Field(1) }), s.priv)).toBe(false);
    }
  });

  it('make amount the state balance: no other amount can be proven', async () => {
    const s = sample(KIND_MUTUAL_CLOSE, { signed: true });
    const amount = s.pub.amount;
    expect(await holds(KIND_MUTUAL_CLOSE, withPub(s, { amount: amount.sub(1) }), s.priv)).toBe(false);
    expect(await holds(KIND_MUTUAL_CLOSE, withPub(s, { amount: amount.add(1) }), s.priv)).toBe(false);
    const g = sample(KIND_MUTUAL_CLOSE);
    expect(await holds(KIND_MUTUAL_CLOSE, withPub(g, { amount: g.pub.amount.sub(1) }), g.priv)).toBe(false);
  });

  it('require amount ≤ size, and size to be the note deposit size', async () => {
    // A signed state whose balance exceeds the deposit.
    const over = sample(KIND_MUTUAL_CLOSE, { signed: true, balance: defaultWithdrawal().size + 1n });
    expect(await holds(KIND_MUTUAL_CLOSE, over.pub, over.priv)).toBe(false);
    const full = sample(KIND_MUTUAL_CLOSE, { signed: true, balance: defaultWithdrawal().size });
    expect(await holds(KIND_MUTUAL_CLOSE, full.pub, full.priv)).toBe(true);
    const s = sample(KIND_MUTUAL_CLOSE, { signed: true });
    expect(await holds(KIND_MUTUAL_CLOSE, withPub(s, { size: s.pub.size.add(1) }), s.priv)).toBe(false);
  });

  it('fail for an expired note', async () => {
    const expiry = expiryOf(defaultWithdrawal().depositTime);
    const last = sample(KIND_MUTUAL_CLOSE, { requestTime: expiry - 1n });
    expect(await holds(KIND_MUTUAL_CLOSE, last.pub, last.priv)).toBe(true);
    for (const requestTime of [expiry, expiry + 1n]) {
      const s = sample(KIND_MUTUAL_CLOSE, { requestTime });
      expect(await holds(KIND_MUTUAL_CLOSE, s.pub, s.priv)).toBe(false);
    }
  });

  it('fail for a root the note is not in, and for a nullifier of another state', async () => {
    const s = sample(KIND_MUTUAL_CLOSE);
    expect(await holds(KIND_MUTUAL_CLOSE, withPub(s, { root: s.pub.root.add(1) }), s.priv)).toBe(false);
    expect(await holds(KIND_MUTUAL_CLOSE, withPub(s, { nullifier: nullifier(s.priv.secret, Field(5)) }), s.priv)).toBe(false);
  });

  it('fail for a state signed by another key, and for a signed state flagged as genesis', async () => {
    const s = sample(KIND_MUTUAL_CLOSE, { signed: true });
    const other = PrivateKey.fromBigInt(2n);
    const sig = Signature.create(other, stateFields({
      vault: s.pub.vault, commitment: s.note.stateCommitment, anchor: s.priv.anchor,
    }));
    expect(await holds(KIND_MUTUAL_CLOSE, s.pub, withPriv(s, { signature: sig }))).toBe(false);
    expect(await holds(KIND_MUTUAL_CLOSE, s.pub, withPriv(s, { isGenesis: Bool(true) }))).toBe(false);
  });

  it('bind the destination only as a public input', async () => {
    const s = sample(KIND_OWNERSHIP);
    const other = PrivateKey.fromBigInt(99n).toPublicKey();
    expect(await holds(KIND_OWNERSHIP, withPub(s, { destination: other }), s.priv)).toBe(true);
    expect(s.pub.destination.equals(other).toBoolean()).toBe(false);
  });
});

describe('withdrawal proof', () => {
  it('compiles to a verification key different from the request proof’s, and proves both kinds', async () => {
    const { verificationKey } = await WithdrawalProgram.compile();
    const request = await RequestProgram.compile();
    expect(verificationKey.hash.toString()).not.toBe(request.verificationKey.hash.toString());
    expect(verificationKey.data).not.toBe(request.verificationKey.data);

    const close = sample(KIND_MUTUAL_CLOSE, { signed: true });
    const { proof } = await WithdrawalProgram.mutualClose(close.pub, close.priv);
    expect(await verify(proof, verificationKey)).toBe(true);
    expect(proof.publicInput.kind.toString()).toBe('1');
    expect(proof.publicInput.nullifier.toString()).toBe(close.pub.nullifier.toString());

    const own = sample(KIND_OWNERSHIP);
    const owned = await WithdrawalProgram.ownership(own.pub, own.priv);
    expect(await verify(owned.proof, verificationKey)).toBe(true);
    expect(owned.proof.publicInput.kind.toString()).toBe('3');

    // A proof of one kind cannot be made for the other method.
    await expect(WithdrawalProgram.ownership(close.pub, close.priv)).rejects.toThrow();
  }, 1_800_000);
});

describe('withdrawal vectors', () => {
  const file = JSON.parse(readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8'));
  it('are reproduced, and satisfy the constraints', async () => {
    expect(file.withdrawalProofs.length).toBe(WITHDRAWAL_SAMPLES.length);
    for (const [i, o] of WITHDRAWAL_SAMPLES.entries()) {
      const s = buildWithdrawal(o);
      expect(withdrawalVector(s, o)).toEqual(file.withdrawalProofs[i]);
      expect(await holds(o.kind, s.pub, s.priv)).toBe(true);
    }
  });
});
