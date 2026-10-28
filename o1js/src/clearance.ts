// The clearance the zk edge signs under the state key: one state's nullifier may close to one destination.
// Mirrored by zk-note/src/clearance.rs, which documents the layout.
import { Bool, Field, PrivateKey, PublicKey, Signature } from 'o1js';
import { TAGS, tagToBigint } from './primitives.js';

export interface ClearanceMessage {
  stateKey: PublicKey;
  nullifier: Field;
  destination: PublicKey;
}

/** `[clearanceTag, stateKey.x, stateKey.isOdd, nullifier, destination.x, destination.isOdd]`. */
export const clearanceFields = (m: ClearanceMessage): Field[] => [
  Field(tagToBigint(TAGS.clearance)),
  m.stateKey.x, m.stateKey.isOdd.toField(), m.nullifier, m.destination.x, m.destination.isOdd.toField(),
];

/** Mina Schnorr under the devnet network ID, like the state message. */
export const signClearance = (key: PrivateKey, m: ClearanceMessage): Signature =>
  Signature.create(key, clearanceFields(m));

export const verifyClearance = (sig: Signature, m: ClearanceMessage): Bool =>
  sig.verify(m.stateKey, clearanceFields(m));
