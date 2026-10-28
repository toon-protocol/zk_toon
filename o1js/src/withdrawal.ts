// The withdrawal proof: a payer proves it holds a zk note's current state and what that state is worth,
// to leave the vault (mutual close) or to show the zk edge it owns the note (ownership). Separate from
// the request proof, so it has its own verification key. Escape (#9) adds its method here.
import { Bool, Field, PublicKey, Scalar, Signature, Struct, ZkProgram } from 'o1js';
import { NoteWitness } from './note-tree.js';
import { U64_BITS, checkNoteState } from './note-state.js';

/** The withdrawal kinds, a public input. 0 is invalid. */
export enum WithdrawalKind {
  mutualClose = 1,
  /** Reserved for #9. */
  escape = 2,
  ownership = 3,
}

/** The public inputs, in this order. The connector reads this layout. */
export class WithdrawalPublic extends Struct({
  kind: Field,
  /** The state key the zk edge signs state and clearances under. */
  vault: PublicKey,
  root: Field,
  nullifier: Field,
  /** Zero for mutual close and ownership. */
  nextNullifier: Field,
  /** The state's balance. */
  amount: Field,
  /** The note's deposit size. */
  size: Field,
  /** Where the balance goes; an ownership proof binds the destination its holder wants cleared. */
  destination: PublicKey,
  /** Zero for mutual close and ownership. */
  validUntil: Field,
  requestTime: Field,
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

/** The checks of a mutual close or an ownership proof; `kind` is the method's own. */
export function checkWithdrawal(kind: WithdrawalKind, pub: WithdrawalPublic, priv: WithdrawalPrivate) {
  pub.kind.assertEquals(kind);
  pub.nextNullifier.assertEquals(0);
  pub.validUntil.assertEquals(0);

  // `amount` is the state's balance and `size` the note's deposit size.
  checkNoteState(pub, { ...priv, size: pub.size, balance: pub.amount });

  // amount ≤ size.
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
        checkWithdrawal(WithdrawalKind.mutualClose, pub, priv);
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
