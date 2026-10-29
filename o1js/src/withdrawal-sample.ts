// Builds withdrawal-proof inputs outside any circuit, for the tests and for the shared vectors.
import { Field, PrivateKey, PublicKey } from 'o1js';
import type { NoteTree } from './note-tree.js';
import { buildSample, defaultSample, type Sample, type SampleOptions } from './request-sample.js';
import { KIND_MUTUAL_CLOSE, KIND_OWNERSHIP, WithdrawalPrivate, WithdrawalPublic } from './withdrawal.js';

export interface WithdrawalOptions extends SampleOptions {
  kind: number;
  destinationSecret: bigint;
}

export const defaultWithdrawal = (kind = KIND_MUTUAL_CLOSE): WithdrawalOptions => ({
  ...defaultSample(), kind, destinationSecret: 77n,
});

export interface WithdrawalSample {
  pub: WithdrawalPublic;
  priv: WithdrawalPrivate;
  /** The note's request sample: tree, state key, the state's commitment. */
  note: Sample;
  destination: PublicKey;
}

/** A withdrawal of the sample's state: `amount` is its balance, `size` its deposit size. */
export function buildWithdrawal(
  o: WithdrawalOptions, existing?: { tree: NoteTree; index: bigint }
): WithdrawalSample {
  const note = buildSample(o, existing);
  const destination = PrivateKey.fromBigInt(o.destinationSecret).toPublicKey();
  const amount = note.priv.balance;
  const pub = new WithdrawalPublic({
    kind: Field(o.kind), vault: note.pub.vault, root: note.pub.root, nullifier: note.pub.nullifier,
    nextNullifier: Field(0), amount, size: note.priv.size, destination, validUntil: Field(0),
    requestTime: note.pub.requestTime,
  });
  const p = note.priv;
  const priv = new WithdrawalPrivate({
    secret: p.secret, index: p.index, depositTime: p.depositTime, expiry: p.expiry, path: p.path,
    blinding: p.blinding, anchor: p.anchor, isGenesis: p.isGenesis, signature: p.signature,
    prevNullifier: p.prevNullifier, prevAnchor: p.prevAnchor,
  });
  return { pub, priv, note, destination };
}

/** The samples the shared vector file pins: an ownership proof of a genesis state, a mutual close of a signed one. */
export const WITHDRAWAL_SAMPLES: WithdrawalOptions[] = [
  { ...defaultWithdrawal(KIND_OWNERSHIP) },
  { ...defaultWithdrawal(KIND_MUTUAL_CLOSE), signed: true, before: 5, destinationSecret: 78n },
];

export const withdrawalVector = (s: WithdrawalSample, o: WithdrawalOptions) => {
  const str = (f: Field) => f.toString();
  const key = (k: PublicKey) => ({ x: str(k.x), isOdd: str(k.isOdd.toField()) });
  return {
    public: {
      kind: str(s.pub.kind), vault: key(s.pub.vault), root: str(s.pub.root), nullifier: str(s.pub.nullifier),
      nextNullifier: str(s.pub.nextNullifier), amount: str(s.pub.amount), size: str(s.pub.size),
      destination: key(s.pub.destination), validUntil: str(s.pub.validUntil), requestTime: str(s.pub.requestTime),
    },
    // What Rust needs to recompute the nullifier.
    private: {
      secret: o.secret.toString(), anchor: str(s.priv.anchor), isGenesis: s.priv.isGenesis.toBoolean(),
      depositTime: str(s.priv.depositTime), expiry: str(s.priv.expiry),
    },
  };
};
