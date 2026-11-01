// Builds withdrawal-proof inputs outside any circuit, for the tests, the vault tests and the shared vectors.
import { Bool, Field, PrivateKey, PublicKey, Scalar, Signature } from 'o1js';
import { commit } from './balance.js';
import { NoteTree } from './note-tree.js';
import { DEPOSIT_SIZES, REQUEST_MAX_AGE_SLOTS, SLOTS_PER_DAY, expiryOf } from './policy.js';
import { commitSecret, nextAnchor, nullifier } from './primitives.js';
import { stateFields } from './state.js';
import { WithdrawalKind, WithdrawalPrivate, WithdrawalPublic } from './withdrawal.js';
import { stateChain } from './request-sample.js';

export interface WithdrawalOptions {
  kind: WithdrawalKind;
  secret: bigint;
  /** The note's index in `tree`. */
  index: bigint;
  size: bigint;
  depositTime: bigint;
  requestTime: bigint;
  /** A signed state; otherwise the note is at genesis and its balance is the deposit size. */
  signed: boolean;
  /** A signed state's place in the note's chain of states: 1 (the default) is genesis's successor. */
  step?: number;
  balance: bigint;
  blinding: bigint;
  stateKey: PrivateKey;
  destination: PublicKey;
  /** Escape only: what it concedes (default 0) and its last landing time (default requestTime + 10 min). */
  conceded?: bigint;
  validUntil?: bigint;
}

/** The default `validUntil` of an escape sample, after its `requestTime`. */
export const ESCAPE_VALIDITY_SLOTS = REQUEST_MAX_AGE_SLOTS;

/** Inputs for the note at `o.index` of `tree`, which must hold that note. */
export function buildWithdrawal(tree: NoteTree, o: WithdrawalOptions) {
  const secret = Field(o.secret);
  const vault = o.stateKey.toPublicKey();
  const balance = o.signed ? o.balance : o.size;
  const stateCommitment = commit(Scalar.from(balance), Scalar.from(o.blinding));

  const { anchor, prevNullifier, prevAnchor } = stateChain(secret, o.signed ? o.step ?? 1 : 0);
  const signature = o.signed
    ? Signature.create(o.stateKey, stateFields({ vault, commitment: stateCommitment, anchor }))
    : Signature.create(o.stateKey, [Field(0)]);

  const current = nullifier(secret, anchor);
  const isEscape = o.kind === WithdrawalKind.escape;
  const pub = new WithdrawalPublic({
    kind: Field(o.kind), vault, root: tree.root, nullifier: current,
    nextNullifier: isEscape ? nullifier(secret, nextAnchor(current)) : Field(0),
    amount: Field(balance), size: Field(o.size), destination: o.destination,
    validUntil: Field(isEscape ? o.validUntil ?? o.requestTime + ESCAPE_VALIDITY_SLOTS : 0n),
    requestTime: Field(o.requestTime), conceded: Field(isEscape ? o.conceded ?? 0n : 0n),
  });
  const priv = new WithdrawalPrivate({
    secret, index: Field(o.index), depositTime: Field(o.depositTime), expiry: Field(expiryOf(o.depositTime)),
    path: tree.witness(o.index), blinding: Scalar.from(o.blinding), anchor, isGenesis: Bool(!o.signed),
    signature, prevNullifier, prevAnchor,
  });
  return { pub, priv };
}

/** A tree holding `before` other deposits, then the sample's note. */
export function sampleTree(o: { secret: bigint; size: bigint; depositTime: bigint }, before: number) {
  const tree = new NoteTree();
  for (let i = 0; i < before; i++) {
    tree.append({ commitment: commitSecret(Field(BigInt(i + 1))), size: Field(DEPOSIT_SIZES[0]), depositTime: Field(o.depositTime) });
  }
  const index = tree.append({ commitment: commitSecret(Field(o.secret)), size: Field(o.size), depositTime: Field(o.depositTime) });
  return { tree, index };
}

export const defaultWithdrawal = (kind = WithdrawalKind.mutualClose): Omit<WithdrawalOptions, 'index'> => {
  const depositTime = 900_000n;
  return {
    kind, secret: 123456789012345678901234567890n, size: DEPOSIT_SIZES[0], depositTime,
    requestTime: depositTime + 8n * SLOTS_PER_DAY, signed: false, balance: 4_000_000_000n, blinding: 777_000_111n,
    stateKey: PrivateKey.fromBigInt(1n), destination: PrivateKey.fromBigInt(7n).toPublicKey(),
  };
};

/** A sample on a tree of `before` other deposits. */
export function withdrawalSample(over: Partial<Omit<WithdrawalOptions, 'index'>> = {}, before = 3) {
  const o = { ...defaultWithdrawal(), ...over };
  const { tree, index } = sampleTree(o, before);
  return { ...buildWithdrawal(tree, { ...o, index }), tree, options: { ...o, index } };
}

/**
 * The samples the shared vector file pins, in its order: an ownership proof at genesis and a mutual close
 * of a signed state (#8), then an escape of a signed state conceding part of its balance (#9).
 */
export const WITHDRAWAL_VECTOR_SAMPLES: { options: Omit<WithdrawalOptions, 'index'>; before: number }[] = [
  { options: { ...defaultWithdrawal(WithdrawalKind.ownership), destination: PrivateKey.fromBigInt(77n).toPublicKey() }, before: 3 },
  {
    options: { ...defaultWithdrawal(WithdrawalKind.mutualClose), signed: true, destination: PrivateKey.fromBigInt(78n).toPublicKey() },
    before: 5,
  },
  {
    options: {
      ...defaultWithdrawal(WithdrawalKind.escape), signed: true, conceded: 10_000_000n,
      destination: PrivateKey.fromBigInt(9n).toPublicKey(),
    },
    before: 4,
  },
];

/**
 * A sample's public inputs, and the private values Rust needs to recompute the nullifier. `conceded`,
 * appended by the escape, is listed for an escape only, so the entries made before it keep their bytes.
 */
export function withdrawalVector(sample: { options: Omit<WithdrawalOptions, 'index'>; before: number }) {
  const { pub, priv, options: o } = withdrawalSample(sample.options, sample.before);
  const str = (f: Field) => f.toString();
  const key = (k: PublicKey) => ({ x: str(k.x), isOdd: str(k.isOdd.toField()) });
  return {
    public: {
      kind: str(pub.kind), vault: key(pub.vault), root: str(pub.root), nullifier: str(pub.nullifier),
      nextNullifier: str(pub.nextNullifier), amount: str(pub.amount), size: str(pub.size),
      destination: key(pub.destination), validUntil: str(pub.validUntil), requestTime: str(pub.requestTime),
      ...(o.kind === WithdrawalKind.escape ? { conceded: str(pub.conceded) } : {}),
    },
    private: {
      secret: str(priv.secret), anchor: str(priv.anchor), isGenesis: priv.isGenesis.toBoolean(),
      depositTime: str(priv.depositTime), expiry: str(priv.expiry),
    },
  };
}
