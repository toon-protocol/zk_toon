// The clearance: the zk edge's signature, under the state key, agreeing that one state's nullifier may
// close to one destination. Mirrored by zk-note/src/clearance.rs, which documents the layout.
import { Bool, Field, PrivateKey, PublicKey, Signature } from 'o1js';
import { TAGS, tagToBigint } from './primitives.js';

export interface ClearanceMessage {
  stateKey: PublicKey;
  nullifier: Field;
  destination: PublicKey;
}

/** The clearance tag leads the message, so a clearance never passes as a state message. */
export const CLEARANCE_TAG = tagToBigint(TAGS.clearance);

/** `[clearanceTag, stateKey.x, stateKey.isOdd, nullifier, destination.x, destination.isOdd]`. */
export const clearanceFields = (m: ClearanceMessage): Field[] => [
  Field(CLEARANCE_TAG),
  m.stateKey.x, m.stateKey.isOdd.toField(),
  m.nullifier,
  m.destination.x, m.destination.isOdd.toField(),
];

/** Mina Schnorr under the devnet network ID, the state message's rule. */
export const signClearance = (stateKey: PrivateKey, m: ClearanceMessage): Signature =>
  Signature.create(stateKey, clearanceFields(m));

/** True when `sig` is the state key's clearance of this nullifier to this destination. */
export const verifyClearance = (sig: Signature, m: ClearanceMessage): Bool =>
  sig.verify(m.stateKey, clearanceFields(m));
