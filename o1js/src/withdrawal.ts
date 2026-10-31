// The withdrawal proof: a payer proves it holds a zk note's current state and what that state is worth,
// to leave the vault (mutual close) or to show the zk edge it owns the note (ownership). Separate from
// the request proof, so it has its own verification key. An escape proves the same state and also
// publishes the next state's nullifier, a conceded amount and how long the proof may be used.
import { Bool, Field, PublicKey, Scalar, Signature, Struct, ZkProgram } from 'o1js';
import { NoteWitness } from './note-tree.js';
import { U64_BITS, checkNoteState } from './note-state.js';
import { nextAnchor, nullifier } from './primitives.js';

/** The withdrawal kinds, a public input. 0 is invalid. */
export enum WithdrawalKind {
  mutualClose = 1,
  escape = 2,
  ownership = 3,
}

/**
 * The public inputs, in this order. The connector reads this layout. `conceded` was appended by the
 * escape (#9), so every other input keeps its position.
 */
export class WithdrawalPublic extends Struct({
  kind: Field,
  /** The state key the zk edge signs state and clearances under. */
  vault: PublicKey,
  root: Field,
  nullifier: Field,
  /** An escape's next-state nullifier, `nullifier(secret, nextAnchor(nullifier))`; zero otherwise. */
  nextNullifier: Field,
  /** The state's balance. */
  amount: Field,
  /** The note's deposit size. */
  size: Field,
  /** Where the balance goes; an ownership proof binds the destination its holder wants cleared. */
  destination: PublicKey,
  /** The last slot an escape may land at; zero otherwise. `requestTime ≤ validUntil < expiry`. */
  validUntil: Field,
  requestTime: Field,
  /** What an escape gives up of its balance, at most the balance; zero otherwise. */
  conceded: Field,
}) {}

/**
 * What only the payer knows. The note's expiry stays private: it follows from the deposit time,
 * which is public on chain, so publishing it would link the withdrawal to its deposit.
 */
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

/** The checks of every withdrawal kind; `kind` is the method's own. */
export function checkWithdrawal(kind: WithdrawalKind, pub: WithdrawalPublic, priv: WithdrawalPrivate) {
  pub.kind.assertEquals(kind);

  // `amount` is the state's balance and `size` the note's deposit size.
  checkNoteState(pub, { ...priv, size: pub.size, balance: pub.amount });

  // amount ≤ size.
  pub.size.toBits(U64_BITS);
  pub.size.sub(pub.amount).toBits(U64_BITS);

  if (kind === WithdrawalKind.escape) {
    // The next state's nullifier, so the escape consumes it too and a defeat can name it.
    pub.nextNullifier.assertEquals(nullifier(priv.secret, nextAnchor(pub.nullifier)));
    // conceded ≤ amount.
    pub.conceded.toBits(U64_BITS);
    pub.amount.sub(pub.conceded).toBits(U64_BITS);
    // requestTime ≤ validUntil < expiry: the note is unexpired whenever the vault accepts the escape.
    pub.validUntil.toBits(U64_BITS);
    pub.validUntil.sub(pub.requestTime).toBits(U64_BITS);
    priv.expiry.sub(pub.validUntil).sub(1).toBits(U64_BITS);
  } else {
    pub.nextNullifier.assertEquals(0);
    pub.validUntil.assertEquals(0);
    pub.conceded.assertEquals(0);
  }
}

export const WithdrawalProgram = ZkProgram({
  name: 'zk-toon-withdrawal',
  publicInput: WithdrawalPublic,
  methods: {
    mutualClose: {
      privateInputs: [WithdrawalPrivate],
      async method(pub: WithdrawalPublic, priv: WithdrawalPrivate) {
        checkWithdrawal(WithdrawalKind.mutualClose, pub, priv);
      },
    },
    escape: {
      privateInputs: [WithdrawalPrivate],
      async method(pub: WithdrawalPublic, priv: WithdrawalPrivate) {
        checkWithdrawal(WithdrawalKind.escape, pub, priv);
      },
    },
    ownership: {
      privateInputs: [WithdrawalPrivate],
      async method(pub: WithdrawalPublic, priv: WithdrawalPrivate) {
        checkWithdrawal(WithdrawalKind.ownership, pub, priv);
      },
    },
  },
});

export class WithdrawalProof extends ZkProgram.Proof(WithdrawalProgram) {}
