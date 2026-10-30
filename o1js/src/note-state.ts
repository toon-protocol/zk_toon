// The checks every proof about a zk note's current state makes: the request proof and the withdrawal
// proof both call `checkNoteState`, so they agree on what a note and its current state are.
import { Bool, Field, Group, PublicKey, Scalar, Signature } from 'o1js';
import { commit } from './balance.js';
import { NoteWitness } from './note-tree.js';
import { expiryOfField } from './policy.js';
import { commitSecret, genesisAnchor, leaf, nextAnchor, nullifier } from './primitives.js';
import { verifyState } from './state.js';

/** Amounts and times are bounded to 64 bits so no comparison can wrap the field. */
export const U64_BITS = 64;

/** What a proof publishes about the note's state. */
export interface NoteStatePublic {
  /** The state key the zk edge signs state under. */
  vault: PublicKey;
  root: Field;
  requestTime: Field;
  nullifier: Field;
}

/** What only the payer knows. */
export interface NoteStateWitness {
  secret: Field;
  index: Field;
  size: Field;
  depositTime: Field;
  expiry: Field;
  path: NoteWitness;
  /** The state's balance and blinding. */
  balance: Field;
  blinding: Scalar;
  anchor: Field;
  isGenesis: Bool;
  /** Signed state only; dummies for a genesis state. */
  signature: Signature;
  prevNullifier: Field;
  prevAnchor: Field;
}

/**
 * The note is in the tree at `root`, not expired at `requestTime`, its state is the genesis state or
 * one signed by `vault` at the derived anchor, and `nullifier` is that state's nullifier. The balance
 * is bounded to 64 bits. Returns the state's balance commitment.
 */
export function checkNoteState(pub: NoteStatePublic, w: NoteStateWitness): Group {
  // Membership: the leaf is in the tree at `root`, at its own index, and its expiry follows from its deposit time.
  const commitment = commitSecret(w.secret);
  w.expiry.assertEquals(expiryOfField(w.depositTime));
  w.depositTime.toBits(U64_BITS);
  w.expiry.toBits(U64_BITS);
  w.path.calculateRoot(leaf(w.index, commitment, w.size, w.depositTime, w.expiry)).assertEquals(pub.root);
  w.path.calculateIndex().assertEquals(w.index);

  // Not expired: requestTime < expiry.
  pub.requestTime.toBits(U64_BITS);
  w.expiry.sub(pub.requestTime).sub(1).toBits(U64_BITS);

  const stateCommitment = commit(Scalar.fromBits(w.balance.toBits(U64_BITS)), w.blinding);

  // The state is the genesis state, or one the vault signed as this note's next state.
  const genesisOk = w.isGenesis
    .and(w.anchor.equals(genesisAnchor(commitment)))
    .and(w.balance.equals(w.size));
  const signedOk = w.isGenesis
    .not()
    .and(verifyState(w.signature, { vault: pub.vault, commitment: stateCommitment, anchor: w.anchor }))
    .and(w.anchor.equals(nextAnchor(w.prevNullifier)))
    .and(w.prevNullifier.equals(nullifier(w.secret, w.prevAnchor)));
  genesisOk.or(signedOk).assertTrue();

  nullifier(w.secret, w.anchor).assertEquals(pub.nullifier);
  return stateCommitment;
}
