import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Bool, Field, PrivateKey, Provable, Signature, verify } from 'o1js';
import { DEPOSIT_SIZES, SLOT_SECONDS, expiryOf } from './policy.js';
import { nextAnchor, nullifier } from './primitives.js';
import { RequestProgram } from './request.js';
import { WithdrawalKind, WithdrawalPrivate, WithdrawalProgram, WithdrawalPublic, checkWithdrawal } from './withdrawal.js';
import { WITHDRAWAL_VECTOR_SAMPLES, withdrawalSample, withdrawalVector } from './withdrawal-sample.js';

// Proofs off: the constraints are checked, no proof is made.
const holds = async (kind: WithdrawalKind, pub: WithdrawalPublic, priv: WithdrawalPrivate) => {
  try {
    await Provable.runAndCheck(() => {
      const p = Provable.witness(WithdrawalPublic, () => pub);
      const w = Provable.witness(WithdrawalPrivate, () => priv);
      checkWithdrawal(kind, p, w);
    });
    return true;
  } catch {
    return false;
  }
};
const withPub = (s: { pub: WithdrawalPublic }, over: Partial<WithdrawalPublic>) => new WithdrawalPublic({ ...s.pub, ...over });

const { mutualClose, escape, ownership } = WithdrawalKind;

describe('withdrawal proof constraints', () => {
  it('hold for a mutual close and an ownership proof, of a genesis and a signed state', async () => {
    for (const kind of [mutualClose, ownership]) {
      for (const signed of [false, true]) {
        const s = withdrawalSample({ kind, signed });
        expect(await holds(kind, s.pub, s.priv)).toBe(true);
      }
    }
  });

  it('fix the kind to the method', async () => {
    const close = withdrawalSample({ kind: mutualClose });
    expect(await holds(ownership, close.pub, close.priv)).toBe(false);
    const own = withdrawalSample({ kind: ownership });
    expect(await holds(mutualClose, own.pub, own.priv)).toBe(false);
    for (const kind of [0, WithdrawalKind.escape]) {
      expect(await holds(mutualClose, withPub(close, { kind: Field(kind) }), close.priv)).toBe(false);
    }
  });

  it('enforce zero nextNullifier, validUntil and conceded', async () => {
    for (const kind of [mutualClose, ownership]) {
      const s = withdrawalSample({ kind });
      expect(await holds(kind, withPub(s, { nextNullifier: Field(1) }), s.priv)).toBe(false);
      expect(await holds(kind, withPub(s, { validUntil: Field(1) }), s.priv)).toBe(false);
      expect(await holds(kind, withPub(s, { conceded: Field(1) }), s.priv)).toBe(false);
    }
  });

  it('bind amount to the state balance and size to the deposit size', async () => {
    const s = withdrawalSample({ signed: true, balance: 4_000_000_000n });
    expect(await holds(mutualClose, withPub(s, { amount: s.pub.amount.add(1) }), s.priv)).toBe(false);
    expect(await holds(mutualClose, withPub(s, { amount: s.pub.amount.sub(1) }), s.priv)).toBe(false);
    expect(await holds(mutualClose, withPub(s, { size: Field(DEPOSIT_SIZES[1]) }), s.priv)).toBe(false);
    // A genesis state's balance is the deposit size.
    const g = withdrawalSample();
    expect(g.pub.amount.toBigInt()).toBe(DEPOSIT_SIZES[0]);
  });

  it('refuse a signed balance above the deposit size, even one the zk edge signed', async () => {
    const at = withdrawalSample({ signed: true, balance: DEPOSIT_SIZES[0] });
    expect(await holds(mutualClose, at.pub, at.priv)).toBe(true);
    const above = withdrawalSample({ signed: true, balance: DEPOSIT_SIZES[0] + 1n });
    expect(await holds(mutualClose, above.pub, above.priv)).toBe(false);
    const zero = withdrawalSample({ signed: true, balance: 0n });
    expect(await holds(mutualClose, zero.pub, zero.priv)).toBe(true);
  });

  it('refuse an expired note', async () => {
    const expiry = expiryOf(900_000n);
    const last = withdrawalSample({ requestTime: expiry - 1n });
    expect(await holds(mutualClose, last.pub, last.priv)).toBe(true);
    const s = withdrawalSample({ requestTime: expiry });
    expect(await holds(mutualClose, s.pub, s.priv)).toBe(false);
  });

  it('refuse a state signed by another key, a root the note is not in, and another nullifier', async () => {
    const s = withdrawalSample({ signed: true });
    const other = Signature.create(PrivateKey.fromBigInt(2n), [Field(0)]);
    expect(await holds(mutualClose, s.pub, new WithdrawalPrivate({ ...s.priv, signature: other }))).toBe(false);
    expect(await holds(mutualClose, withPub(s, { root: s.pub.root.add(1) }), s.priv)).toBe(false);
    expect(await holds(mutualClose, withPub(s, { nullifier: nullifier(s.priv.secret, s.priv.prevAnchor) }), s.priv)).toBe(false);
    // A signed state flagged as genesis.
    expect(await holds(mutualClose, s.pub, new WithdrawalPrivate({ ...s.priv, isGenesis: Bool(true) }))).toBe(false);
  });

  it('bind the destination only as a public input', async () => {
    const s = withdrawalSample({ kind: ownership });
    const other = PrivateKey.fromBigInt(99n).toPublicKey();
    expect(await holds(ownership, withPub(s, { destination: other }), s.priv)).toBe(true);
    expect(s.pub.destination.equals(other).toBoolean()).toBe(false);
  });
});

describe('escape proof constraints', () => {
  const hour = 3_600n / SLOT_SECONDS;
  const esc = (over: Parameters<typeof withdrawalSample>[0] = {}) =>
    withdrawalSample({ kind: escape, signed: true, balance: 4_000_000_000n, conceded: 10_000_000n, ...over });

  it('hold for an escape of a genesis and a signed state, publishing the next state nullifier', async () => {
    for (const signed of [false, true]) {
      const s = esc({ signed });
      expect(await holds(escape, s.pub, s.priv)).toBe(true);
      // The next state's anchor is derived from this state's nullifier.
      const next = nullifier(s.priv.secret, nextAnchor(s.pub.nullifier));
      expect(s.pub.nextNullifier.toBigInt()).toBe(next.toBigInt());
    }
    const s = esc();
    expect(await holds(mutualClose, s.pub, s.priv)).toBe(false);
  });

  it('refuse a next nullifier other than the derived one', async () => {
    const s = esc();
    for (const nextNullifier of [Field(0), s.pub.nextNullifier.add(1), s.pub.nullifier]) {
      expect(await holds(escape, withPub(s, { nextNullifier }), s.priv)).toBe(false);
    }
  });

  it('bound the concession by the balance', async () => {
    expect(await holds(escape, esc({ conceded: 4_000_000_000n }).pub, esc({ conceded: 4_000_000_000n }).priv)).toBe(true);
    expect(await holds(escape, esc({ conceded: 0n }).pub, esc({ conceded: 0n }).priv)).toBe(true);
    const over = esc({ conceded: 4_000_000_001n });
    expect(await holds(escape, over.pub, over.priv)).toBe(false);
  });

  it('require requestTime ≤ validUntil < expiry', async () => {
    const expiry = expiryOf(900_000n);
    const requestTime = expiry - 2n * hour;
    for (const [validUntil, ok] of [
      [requestTime, true], [expiry - 1n, true], [requestTime - 1n, false], [expiry, false],
    ] as const) {
      const s = esc({ requestTime, validUntil });
      expect(await holds(escape, s.pub, s.priv)).toBe(ok);
    }
  });
});

describe('withdrawal proof vectors', () => {
  const file = JSON.parse(readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8'));
  it('cover an ownership proof, a mutual close and an escape, are reproduced, and satisfy the constraints', async () => {
    expect(file.withdrawalProofs.map((v: any) => Number(v.public.kind))).toEqual([ownership, mutualClose, escape]);
    for (const [i, sample] of WITHDRAWAL_VECTOR_SAMPLES.entries()) {
      expect(withdrawalVector(sample)).toEqual(file.withdrawalProofs[i]);
      const { pub, priv, options } = withdrawalSample(sample.options, sample.before);
      expect(await holds(options.kind, pub, priv)).toBe(true);
    }
    console.log(`vector cases run: ${WITHDRAWAL_VECTOR_SAMPLES.length}`);
  });
});

describe('withdrawal proof', () => {
  it('compiles to its own verification key, then proves and verifies a mutual close and an ownership proof', async () => {
    const request = await RequestProgram.compile();
    const { verificationKey } = await WithdrawalProgram.compile();
    expect(verificationKey.hash.toString()).not.toBe(request.verificationKey.hash.toString());

    const close = withdrawalSample({ kind: mutualClose, signed: true });
    const { proof } = await WithdrawalProgram.mutualClose(close.pub, close.priv);
    expect(await verify(proof, verificationKey)).toBe(true);
    expect(proof.publicInput.kind.toBigInt()).toBe(BigInt(mutualClose));

    const own = withdrawalSample({ kind: ownership });
    const owned = await WithdrawalProgram.ownership(own.pub, own.priv);
    expect(await verify(owned.proof, verificationKey)).toBe(true);
    expect(owned.proof.publicInput.kind.toBigInt()).toBe(BigInt(ownership));

    // A proof of one kind cannot be made for the other method.
    await expect(WithdrawalProgram.ownership(close.pub, close.priv)).rejects.toThrow();
  }, 1_800_000);
});
