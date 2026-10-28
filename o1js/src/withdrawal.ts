// The withdrawal proof: a payer proves they hold an unexpired note's current state and withdraws its balance.
// A ZkProgram of its own, so the connector pins its verification key apart from the request proof's. Methods:
// mutual close (the vault pays it, with the zk edge's clearance) and ownership (shown only to the zk edge).
// Escape is added by #9, as kind 2.
import { Bool, Field, PublicKey, Scalar, Signature, Struct, ZkProgram } from 'o1js';
import { NoteWitness } from './note-tree.js';
import { checkNoteState } from './request.js';

const U64_BITS = 64;

export const KIND_MUTUAL_CLOSE = 1;
export const KIND_ESCAPE = 2;
export const KIND_OWNERSHIP = 3;

/**
 * The public inputs, in the order the connector reads them. `vault` is the state key. Note expiry is not
 * among them: it is deposit time + 180 days, and deposit times are public, so it would link a withdrawal
 * to its deposit.
 */
export class WithdrawalPublic extends Struct({
  kind: Field,
  vault: PublicKey,
  root: Field,
  nullifier: Field,
  nextNullifier: Field,
  amount: Field,
  size: Field,
  destination: PublicKey,
  validUntil: Field,
  requestTime: Field,
}) {}

export class WithdrawalPrivate extends Struct({
  secret: Field,
  index: Field,
  depositTime: Field,
  expiry: Field,
  path: NoteWitness,
  blinding: Scalar,
  anchor: Field,
  isGenesis: Bool,
  /** Signed state only; dummies for a genesis state. */
  signature: Signature,
  prevNullifier: Field,
  prevAnchor: Field,
}) {}

/** The checks both kinds make; the method fixes `kind`. */
export function checkWithdrawal(kind: number, pub: WithdrawalPublic, priv: WithdrawalPrivate) {
  pub.kind.assertEquals(kind);
  pub.nextNullifier.assertEquals(0);
  pub.validUntil.assertEquals(0);

  // `amount` is the state's balance and `size` the note's deposit size; a balance never exceeds its deposit.
  checkNoteState(pub, { ...priv, balance: pub.amount, size: pub.size });
  pub.size.toBits(U64_BITS);
  pub.size.sub(pub.amount).toBits(U64_BITS);
}

export const WithdrawalProgram = ZkProgram({
  name: 'zk-toon-withdrawal',
  publicInput: WithdrawalPublic,
  methods: {
    mutualClose: {
      privateInputs: [WithdrawalPrivate],
      async method(pub: WithdrawalPublic, priv: WithdrawalPrivate) {
        checkWithdrawal(KIND_MUTUAL_CLOSE, pub, priv);
      },
    },
    ownership: {
      privateInputs: [WithdrawalPrivate],
      async method(pub: WithdrawalPublic, priv: WithdrawalPrivate) {
        checkWithdrawal(KIND_OWNERSHIP, pub, priv);
      },
    },
  },
});

export class WithdrawalProof extends ZkProgram.Proof(WithdrawalProgram) {}
