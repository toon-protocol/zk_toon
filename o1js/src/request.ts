// The request proof, unsubsidised or subsidised: a payer proves that some unspent note in the vault can cover tier `b`,
// without revealing which note. Every derivation comes from primitives.ts, balance.ts and state.ts.
import { Bool, Field, Group, PublicKey, Scalar, Signature, Struct, ZkProgram } from 'o1js';
import { rerandomise } from './balance.js';
import { NoteWitness } from './note-tree.js';
import { U64_BITS, checkNoteState } from './note-state.js';
import { MIN_SUBSIDY_AGE_MS, SUBSIDY_PERIOD_MS, TIERS, subsidyPeriod } from './policy.js';
import { authTag, periodNullifier } from './primitives.js';

/**
 * The public inputs, in the spec's order (#2). The connector reads these fields, and both methods share
 * this layout.
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

/**
 * The subsidised request (ADR 0001): besides the shared checks, the note is at least 7 days old at
 * `requestTime`, `period` is the whole weeks from `vaultCreation` to `requestTime`, `periodNullifier`
 * is derived from the note's secret, index and that period, and `b` is the smallest tier.
 *
 * `vaultCreation` is a private input, not a public one: the public layout is fixed, and the circuit
 * cannot read the vault's state. So this proof shows only that `period` is the week of `requestTime`
 * counted from *some* creation time; a payer who forges the creation time proves another period, and
 * with it another per-period nullifier. What binds the period to the vault is `subsidyPeriodHolds`,
 * which the zk edge must call with the vault's creation time before it trusts the per-period
 * nullifier. The vault itself never needs to: a subsidised proof never raises, and a defeat does not
 * depend on the period.
 */
export function checkSubsidised(pub: RequestPublic, priv: RequestPrivate, vaultCreation: Field) {
  pub.subsidised.assertTrue();
  pub.tier.assertEquals(Field(TIERS[0]));

  // Old enough: requestTime - depositTime >= 7 days. checkRequest bounds requestTime and depositTime.
  pub.requestTime.sub(priv.depositTime).sub(Field(MIN_SUBSIDY_AGE_MS)).toBits(U64_BITS);

  // The period: period * week <= requestTime - vaultCreation < (period + 1) * week. Each side is
  // bounded to 64 bits, so a request before the creation time, or another period, wraps and fails.
  vaultCreation.toBits(U64_BITS);
  pub.period.toBits(U64_BITS);
  const elapsed = pub.requestTime.sub(vaultCreation);
  const weekStart = pub.period.mul(Field(SUBSIDY_PERIOD_MS));
  elapsed.sub(weekStart).toBits(U64_BITS);
  weekStart.add(Field(SUBSIDY_PERIOD_MS - 1n)).sub(elapsed).toBits(U64_BITS);

  periodNullifier(priv.secret, priv.index, pub.period).assertEquals(pub.periodNullifier);
  checkRequest(pub, priv);
}

/**
 * The check that binds a verified request proof's period to the vault (spec #2: "the period number is
 * whole weeks since the vault's creation"), which the circuit cannot make (see `checkSubsidised`). A
 * subsidised request holds when its `period` is `subsidyPeriod(vaultCreation, requestTime)`; an
 * unsubsidised one when its `period` and `periodNullifier` are zero. The zk edge must call it, with the
 * vault's `creationTime`, before it trusts a subsidised proof's per-period nullifier. Mirrors
 * `RequestPublic::check_subsidy_period` in zk-note.
 */
export function subsidyPeriodHolds(pub: RequestPublic, vaultCreation: bigint): boolean {
  if (!pub.subsidised.toBoolean()) return pub.period.toBigInt() === 0n && pub.periodNullifier.toBigInt() === 0n;
  const period = subsidyPeriod(vaultCreation, pub.requestTime.toBigInt());
  return period !== undefined && pub.period.toBigInt() === period;
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
    subsidised: {
      privateInputs: [RequestPrivate, Field],
      async method(pub: RequestPublic, priv: RequestPrivate, vaultCreation: Field) {
        checkSubsidised(pub, priv, vaultCreation);
      },
    },
  },
});

export class RequestProof extends ZkProgram.Proof(RequestProgram) {}
