// The unsubsidised request proof: a payer proves that some unspent note in the vault can cover tier `b`,
// without revealing which note. Every derivation comes from primitives.ts, balance.ts and state.ts.
import { Bool, Field, Group, PublicKey, Scalar, Signature, Struct, ZkProgram } from 'o1js';
import { rerandomise } from './balance.js';
import { NoteWitness } from './note-tree.js';
import { U64_BITS, checkNoteState } from './note-state.js';
import { authTag } from './primitives.js';

/**
 * The public inputs, in the spec's order (#2). The connector reads these fields, and the subsidised
 * method will share this layout.
 */
export class RequestPublic extends Struct({
  vault: PublicKey,
  root: Field,
  requestTime: Field,
  tier: Field,
  nullifier: Field,
  tag: Field,
  /** The state's balance commitment, re-randomised. */
  commitment: Group,
  subsidised: Bool,
  period: Field,
  periodNullifier: Field,
}) {}

export class RequestPrivate extends Struct({
  secret: Field,
  index: Field,
  size: Field,
  depositTime: Field,
  expiry: Field,
  path: NoteWitness,
  /** The state's balance and blinding. */
  balance: Field,
  blinding: Scalar,
  rerandomBlinding: Scalar,
  anchor: Field,
  isGenesis: Bool,
  /** Signed state only; dummies for a genesis state. */
  signature: Signature,
  prevNullifier: Field,
  prevAnchor: Field,
  /** The request context other than the tier, which is public. */
  edge: Field,
  sessionKeyX: Field,
  sessionKeyIsOdd: Bool,
  requestExpiry: Field,
}) {}

/** The checks shared by the request proof's methods. `pub.tier` is the tier `b` the balance must cover. */
function checkRequest(pub: RequestPublic, priv: RequestPrivate) {
  const stateCommitment = checkNoteState(pub, priv);

  // The balance covers `b`.
  pub.tier.toBits(U64_BITS);
  priv.balance.sub(pub.tier).toBits(U64_BITS);

  authTag(pub.nullifier, {
    edge: priv.edge, sessionKeyX: priv.sessionKeyX, sessionKeyIsOdd: priv.sessionKeyIsOdd,
    tier: pub.tier, expiry: priv.requestExpiry,
  }).assertEquals(pub.tag);

  const rerandomised = rerandomise(stateCommitment, priv.rerandomBlinding);
  rerandomised.x.assertEquals(pub.commitment.x);
  rerandomised.y.assertEquals(pub.commitment.y);
}

/** The unsubsidised request: no allowance is claimed, so the subsidy fields are zero. */
export function checkUnsubsidised(pub: RequestPublic, priv: RequestPrivate) {
  pub.subsidised.assertFalse();
  pub.period.assertEquals(0);
  pub.periodNullifier.assertEquals(0);
  checkRequest(pub, priv);
}

export const RequestProgram = ZkProgram({
  name: 'zk-toon-request',
  publicInput: RequestPublic,
  methods: {
    unsubsidised: {
      privateInputs: [RequestPrivate],
      async method(pub: RequestPublic, priv: RequestPrivate) {
        checkUnsubsidised(pub, priv);
      },
    },
  },
});

export class RequestProof extends ZkProgram.Proof(RequestProgram) {}
