// The unsubsidised request proof: a payer proves that some unspent note in the vault can cover tier `b`,
// without revealing which note. Every derivation comes from primitives.ts, balance.ts and state.ts.
import { Bool, Field, Group, Provable, PublicKey, Scalar, Signature, Struct, ZkProgram } from 'o1js';
import { commit, rerandomise } from './balance.js';
import { NoteWitness } from './note-tree.js';
import { expiryOfField } from './policy.js';
import { authTag, commitSecret, genesisAnchor, leaf, nextAnchor, nullifier } from './primitives.js';
import { verifyState } from './state.js';

/** Amounts and times are bounded to 64 bits so no comparison can wrap the field. */
const AMOUNT_BITS = 64;

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
  // Membership: the leaf is in the tree at `root`, at its own index, and its expiry follows from its deposit time.
  const commitment = commitSecret(priv.secret);
  priv.expiry.assertEquals(expiryOfField(priv.depositTime));
  priv.depositTime.toBits(AMOUNT_BITS);
  priv.expiry.toBits(AMOUNT_BITS);
  priv.path.calculateRoot(leaf(priv.index, commitment, priv.size, priv.depositTime, priv.expiry)).assertEquals(pub.root);
  priv.path.calculateIndex().assertEquals(priv.index);

  // Not expired: requestTime < expiry.
  pub.requestTime.toBits(AMOUNT_BITS);
  priv.expiry.sub(pub.requestTime).sub(1).toBits(AMOUNT_BITS);

  // The balance covers `b`.
  const balanceBits = priv.balance.toBits(AMOUNT_BITS);
  pub.tier.toBits(AMOUNT_BITS);
  priv.balance.sub(pub.tier).toBits(AMOUNT_BITS);
  const stateCommitment = commit(Scalar.fromBits(balanceBits), priv.blinding);

  // The state is the genesis state, or one the vault signed as this note's next state.
  const genesisOk = priv.isGenesis
    .and(priv.anchor.equals(genesisAnchor(commitment)))
    .and(priv.balance.equals(priv.size));
  const signedOk = priv.isGenesis
    .not()
    .and(verifyState(priv.signature, { vault: pub.vault, commitment: stateCommitment, anchor: priv.anchor }))
    .and(priv.anchor.equals(nextAnchor(priv.prevNullifier)))
    .and(priv.prevNullifier.equals(nullifier(priv.secret, priv.prevAnchor)));
  genesisOk.or(signedOk).assertTrue();

  const n = nullifier(priv.secret, priv.anchor);
  n.assertEquals(pub.nullifier);
  authTag(n, {
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
