// The state message the zk edge signs under the vault key. Mirrored by zk-note/src/state.rs, which documents the layout.
import { Bool, Field, Group, PublicKey, Signature } from 'o1js';

export interface StateMessage {
  vault: PublicKey;
  commitment: Group;
  anchor: Field;
}

/** `[vault.x, vault.isOdd, commitment.x, commitment.y, anchor]`. */
export const stateFields = (m: StateMessage): Field[] => [
  m.vault.x, m.vault.isOdd.toField(), m.commitment.x, m.commitment.y, m.anchor,
];

/** Mina Schnorr under the devnet network ID: o1js 3.1.0 hard-codes it, for every vault. */
export const verifyState = (sig: Signature, m: StateMessage): Bool =>
  sig.verify(m.vault, stateFields(m));
