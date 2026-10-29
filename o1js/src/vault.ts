// The vault zkApp. A deposit moves a fixed size into the vault and dispatches an action; a mutual close
// checks a withdrawal proof and the zk edge's clearance and dispatches an action; an escape checks an
// escape proof and dispatches an action; after the challenge window anyone can finalize an escape, which
// dispatches an action too. Within the window, a challenger may defeat an escape with a request proof at its
// next nullifier, or raise its concession with one at its current nullifier; each dispatches an action. A
// permissionless reduce folds every pending action in: deposits into the note tree, consumed nullifiers into
// the nullifier set, escapes, raises and defeats into the pending escapes, and the payouts of closes and
// finalized escapes. A deposit is a note only once reduced, and nothing is paid except at the
// reduce (ADR 0002, "A mutual close pays at the reduce, through the one action stream").
//
// Once notes expire, anyone may sweep: the sweep walks the note tree in index order, adds up the sizes
// of the expired notes it passes, and dispatches a sweep; the reduce pays the treasury what those notes
// left in the vault, `expired − claimed − swept`, without learning which note was withdrawn (ADR 0005).
//
// The vault has no pause: its deploy makes its verification key, permissions and timing unchangeable, so
// no owner action can stop or delay an escape.
import {
  AccountUpdate, Bool, Experimental, Field, IndexedMerkleMap, Permissions, Poseidon, Provable, PublicKey, Signature,
  SmartContract, State, Struct, UInt32, UInt64, Unconstrained, declareMethods, declareState,
} from 'o1js';
import * as policy from './policy.js';
import { verifyClearance } from './clearance.js';
import { type NoteTree, NoteWitness, depositLeaf, emptyNoteRoot } from './note-tree.js';
import { RequestProof, type RequestPublic } from './request.js';
import { WithdrawalKind, WithdrawalProof, type WithdrawalPublic } from './withdrawal.js';

/** How many recent note-tree roots the vault remembers. */
export const ROOT_RING_LENGTH = 8;
/** Mesa slots are 90 s. */
export const SLOT_MS = 90_000n;
/**
 * Actions folded per reduce. A reduce sends two account updates per action (a close's two payouts),
 * so a full batch is 8 unsigned updates: 4 pairs, plus the fee payer and the vault, 6 of Mina's 16
 * segments per transaction. The proving cost binds first: at 5, the reduce plus the check of its batch
 * proof needs more than 2^16 rows, and the vault doesn't compile (#16). `npm run keys` compiles it.
 */
export const REDUCE_BATCH_SIZE = 4;
/** How long after its `requestTime` a mutual close may land: the connector's request-time window. */
export const CLOSE_WINDOW_MS = policy.REQUEST_MAX_AGE_MS;
/** Notes a sweep walks per call, at most. */
export const SWEEP_BATCH_SIZE = 16;
/** The nullifier set holds up to 2^(height − 1) nullifiers. */
export const NULLIFIER_SET_HEIGHT = 32;

/** The consumed nullifiers. The vault stores only the root: a reduce inserts, a close proves absence. */
export class NullifierSet extends IndexedMerkleMap(NULLIFIER_SET_HEIGHT) {}

/**
 * The escapes the vault has recorded, keyed by the escaping state's (current) nullifier. The value is
 * the record's `hash()` while the escape is pending, and 0 once it is finished. A key is a consumed
 * nullifier, so it is never reused.
 */
export class PendingEscapes extends IndexedMerkleMap(NULLIFIER_SET_HEIGHT) {}

/** The kinds of the vault's one action stream. 0 is never dispatched. */
export enum ActionKind {
  deposit = 1,
  mutualClose = 2,
  escape = 3,
  finalize = 4,
  defeat = 5,
  raise = 6,
  sweep = 7,
}

/**
 * A pending escape, as the reduce records it. The vault stores only its hash, at key `nullifier` of the
 * pending escapes. `amount` is the escaping state's balance and `size` the note's deposit size; finalizing
 * pays `amount − conceded` to `destination` and the rest of `size` to the treasury. Anyone may finalize
 * once the block time reaches `deadline`.
 *
 * Before `deadline`, a defeat (a request proof at `nextNullifier`) finishes the record without paying, and
 * a raise (a request proof at `nullifier`) replaces it with one whose `conceded` is lifted.
 */
export class PendingEscape extends Struct({
  nullifier: Field,
  nextNullifier: Field,
  amount: UInt64,
  conceded: UInt64,
  size: UInt64,
  destination: PublicKey,
  deadline: UInt64,
}) {
  hash(): Field {
    return Poseidon.hash(PendingEscape.toFields(this));
  }
  /** What finalizing pays the destination. The escape proof bounds `conceded ≤ amount ≤ size`. */
  payout(): UInt64 {
    return this.amount.sub(this.conceded);
  }
  /**
   * The concession a raise from `evidence` claiming `claimed` lifts this escape to: `min(claimed, b,
   * balance)` (ADR 0004), where `b` is the evidence's tier. A subsidised proof's `b` counts as zero, so it
   * never raises (ADR 0001). The request circuit bounds the tier to 64 bits.
   */
  raisedConcession(evidence: RequestPublic, claimed: UInt64): UInt64 {
    const tier = Provable.if(evidence.subsidised, UInt64, UInt64.zero, UInt64.Unsafe.fromField(evidence.tier));
    const min = (a: UInt64, b: UInt64) => Provable.if(a.lessThan(b), UInt64, a, b);
    return min(min(claimed, tier), this.amount);
  }
}

/**
 * What a reduce did to one pending escape, emitted as the vault's `escape` event (its only event type,
 * so its fields carry no type index): `record` is the escape as recorded or raised when `pending`, or
 * the escape a finalize or defeat finished when not. Replaying these events in order rebuilds the
 * pending escapes to `pendingEscapesRoot`, deadlines included, which the actions alone can't: a
 * deadline is set by the reduce that records the escape. The fields, in order: `pending`, then
 * `nullifier, nextNullifier, amount, conceded, size, destination.x, destination.isOdd, deadline`.
 */
export class EscapeUpdate extends Struct({ pending: Bool, record: PendingEscape }) {}

/**
 * The vault's one fixed-width action. Each kind uses some fields and leaves the rest zero:
 * - a deposit: `commitment`, `size` and `time` (its deposit time);
 * - a mutual close: `nullifier`, `amount`, `size`, `destination` and `time` (its request time);
 * - an escape: those of a close, plus `nextNullifier`, `validUntil` and `conceded`;
 * - a finalize or a defeat: the pending escape it finishes, with `time` its deadline;
 * - a raise: the pending escape as raised, with `time` its deadline and `commitment` the hash of the
 *   record it replaces;
 * - a sweep: `size`, the vault's expired total when it was dispatched.
 * Every dispatched action has `conceded ≤ amount ≤ size`.
 */
export class VaultAction extends Struct({
  kind: Field,
  commitment: Field,
  nullifier: Field,
  nextNullifier: Field,
  amount: UInt64,
  size: UInt64,
  time: UInt64,
  validUntil: UInt64,
  destination: PublicKey,
  conceded: UInt64,
}) {
  static none(): VaultAction {
    return new VaultAction({
      kind: Field(0), commitment: Field(0), nullifier: Field(0), nextNullifier: Field(0), amount: UInt64.zero,
      size: UInt64.zero, time: UInt64.zero, validUntil: UInt64.zero, destination: PublicKey.empty(), conceded: UInt64.zero,
    });
  }
  static deposit(commitment: Field, size: UInt64, depositTime: UInt64): VaultAction {
    return new VaultAction({ ...VaultAction.none(), kind: Field(ActionKind.deposit), commitment, size, time: depositTime });
  }
  /** From a mutual close's public inputs; the withdrawal circuit bounds `amount`, `size` and `requestTime` to 64 bits. */
  static mutualClose(pub: WithdrawalPublic): VaultAction {
    return new VaultAction({
      ...VaultAction.none(), kind: Field(ActionKind.mutualClose), nullifier: pub.nullifier,
      amount: UInt64.Unsafe.fromField(pub.amount), size: UInt64.Unsafe.fromField(pub.size),
      time: UInt64.Unsafe.fromField(pub.requestTime), destination: pub.destination,
    });
  }
  /** From an escape's public inputs; the withdrawal circuit bounds its amounts and times to 64 bits. */
  static escape(pub: WithdrawalPublic): VaultAction {
    return new VaultAction({
      ...VaultAction.mutualClose(pub), kind: Field(ActionKind.escape), nextNullifier: pub.nextNullifier,
      validUntil: UInt64.Unsafe.fromField(pub.validUntil), conceded: UInt64.Unsafe.fromField(pub.conceded),
    });
  }
  static finalize(e: PendingEscape): VaultAction {
    return VaultAction.naming(ActionKind.finalize, e);
  }
  static defeat(e: PendingEscape): VaultAction {
    return VaultAction.naming(ActionKind.defeat, e);
  }
  /** A sweep up to `expired`, the vault's expired total when it was dispatched. */
  static sweep(expired: UInt64): VaultAction {
    return new VaultAction({ ...VaultAction.none(), kind: Field(ActionKind.sweep), size: expired });
  }
  /** Replaces `e` with the record whose concession `evidence` and `claimed` lift it to. */
  static raise(e: PendingEscape, evidence: RequestPublic, claimed: UInt64): VaultAction {
    const raised = new PendingEscape({ ...e, conceded: e.raisedConcession(evidence, claimed) });
    return new VaultAction({ ...VaultAction.naming(ActionKind.raise, raised), commitment: e.hash() });
  }
  private static naming(kind: ActionKind, e: PendingEscape): VaultAction {
    return new VaultAction({
      ...VaultAction.none(), kind: Field(kind), nullifier: e.nullifier, nextNullifier: e.nextNullifier,
      amount: e.amount, conceded: e.conceded, size: e.size, destination: e.destination, time: e.deadline,
    });
  }
  /** The escape a finalize, defeat or raise names, or the record an escape becomes with `deadline`. */
  pendingEscape(deadline: UInt64): PendingEscape {
    return new PendingEscape({
      nullifier: this.nullifier, nextNullifier: this.nextNullifier, amount: this.amount, conceded: this.conceded,
      size: this.size, destination: this.destination, deadline,
    });
  }
}

/**
 * A note a sweep walks past: the deposit as the reduce made it a leaf, and the leaf's witness. A sweep
 * uses each note's size and deposit time, which are public at deposit anyway, and nothing of its fate.
 */
export class SweptNote extends Struct({ commitment: Field, size: UInt64, depositTime: UInt64, path: NoteWitness }) {
  /** The notes at `from` onwards in `tree`, `count` of them, padded to a sweep batch with the empty slot after them. */
  static batch(tree: NoteTree, from: bigint, count: number): SweptNote[] {
    return Array.from({ length: SWEEP_BATCH_SIZE }, (_, i) => {
      const index = from + BigInt(Math.min(i, count));
      const d = i < count ? tree.depositAt(index) : { commitment: Field(0), size: Field(0), depositTime: Field(0) };
      return new SweptNote({
        commitment: d.commitment, size: UInt64.Unsafe.fromField(d.size), depositTime: UInt64.Unsafe.fromField(d.depositTime),
        path: tree.witness(index),
      });
    });
  }
}

/** The accepted deposit sizes, as on-chain state. */
export class DepositSizes extends Struct({ a: UInt64, b: UInt64, c: UInt64 }) {
  static fromPolicy() {
    if (policy.DEPOSIT_SIZES.length !== 3) throw Error('DepositSizes holds exactly three sizes');
    const [a, b, c] = policy.DEPOSIT_SIZES.map((s) => UInt64.from(s));
    return new DepositSizes({ a, b, c });
  }
  has(size: UInt64): Bool {
    return size.equals(this.a).or(size.equals(this.b)).or(size.equals(this.c));
  }
}

/** The latest note-tree roots; a slot is zero until written. `head` is the next slot to overwrite. */
export class RootRing extends Struct({ roots: Provable.Array(Field, ROOT_RING_LENGTH), head: Field }) {
  static empty() {
    return new RootRing({ roots: Array.from({ length: ROOT_RING_LENGTH }, () => Field(0)), head: Field(0) });
  }
  contains(root: Field): Bool {
    // Empty slots hold zero, which is no root.
    return this.roots.reduce((acc, r) => acc.or(r.equals(root)), Bool(false)).and(root.equals(0).not());
  }
  /** Writes `root` over the oldest slot and advances `head`. */
  push(root: Field): RootRing {
    const roots = this.roots.map((r, i) => Provable.if(this.head.equals(i), root, r));
    const advanced = this.head.add(1);
    return new RootRing({ roots, head: Provable.if(advanced.equals(ROOT_RING_LENGTH), Field(0), advanced) });
  }
}

const { BatchReducer } = Experimental;
export const batchReducer = new BatchReducer({ actionType: VaultAction, batchSize: REDUCE_BATCH_SIZE });
export class VaultBatch extends batchReducer.Batch {}
export class VaultBatchProof extends batchReducer.BatchProof {}

export class Vault extends SmartContract {
  // State fields in use: 2 (batch reducer) + 1 + 1 + (8 + 1) + 1 + 3 + 1 + 1 + 1 + 2 + 2 + 1 + 4 = 29 of Mesa's 32.
  actionState = State<Field>();
  actionStack = State<Field>();
  noteRoot = State<Field>();
  nextLeafIndex = State<Field>();
  rootRing = State<RootRing>();
  creationTime = State<UInt64>();
  depositSizes = State<DepositSizes>();
  noteLifetime = State<UInt64>();
  challengeWindow = State<UInt64>();
  /** The root of the nullifier set. */
  nullifierRoot = State<Field>();
  /** The key the zk edge signs state and clearances under; empty until `setup`. */
  stateKey = State<PublicKey>();
  /** The zk edge operator's address: paid what a closed note's balance leaves of its deposit. */
  treasury = State<PublicKey>();
  /** The root of the pending escapes. */
  pendingEscapesRoot = State<Field>();
  /** The index of the next note a sweep walks: every note below it has expired. */
  sweepCursor = State<Field>();
  /** The sizes of the notes below the sweep cursor. */
  expiredTotal = State<UInt64>();
  /**
   * The sizes of the notes the reduce has paid out or holds for a pending escape: each close and each
   * recorded escape adds its note's size, and each defeat takes it back. A finalize leaves it alone.
   */
  claimedTotal = State<UInt64>();
  /** What sweeps have paid the treasury. */
  sweptTotal = State<UInt64>();

  events = { escape: EscapeUpdate };

  /** Deploys with the verification key, permissions and timing locked: the vault has no pause. */
  async deploy(args?: Parameters<SmartContract['deploy']>[0]) {
    await super.deploy(args);
    this.account.permissions.set({
      ...Permissions.default(),
      setVerificationKey: Permissions.VerificationKey.impossibleDuringCurrentVersion(),
      setPermissions: Permissions.impossible(),
      setTiming: Permissions.impossible(),
    });
  }

  /** Pins the creation time to the block timestamp (within a slot) and records the policy. */
  init() {
    super.init();
    const now = this.network.timestamp.get();
    this.network.timestamp.requireBetween(now, now.add(UInt64.from(SLOT_MS)));
    this.creationTime.set(now);
    this.depositSizes.set(DepositSizes.fromPolicy());
    this.noteLifetime.set(UInt64.from(policy.NOTE_LIFETIME_MS));
    this.challengeWindow.set(UInt64.from(policy.CHALLENGE_WINDOW_MS));
    this.actionState.set(BatchReducer.initialActionState);
    this.actionStack.set(BatchReducer.initialActionStack);
    this.noteRoot.set(emptyNoteRoot());
    this.nextLeafIndex.set(Field(0));
    this.rootRing.set(RootRing.empty());
    this.nullifierRoot.set(new NullifierSet().root);
    this.pendingEscapesRoot.set(new PendingEscapes().root);
    this.sweepCursor.set(Field(0));
    this.expiredTotal.set(UInt64.zero);
    this.claimedTotal.set(UInt64.zero);
    this.sweptTotal.set(UInt64.zero);
  }

  /** Once, signed by the vault account: names the state key and the treasury. */
  async setup(stateKey: PublicKey, treasury: PublicKey) {
    this.stateKey.getAndRequireEquals().isEmpty().assertTrue('vault already set up');
    stateKey.isEmpty().assertFalse('empty state key');
    AccountUpdate.createSigned(this.address);
    this.stateKey.set(stateKey);
    this.treasury.set(treasury);
  }

  async deposit(commitment: Field, size: UInt64, depositTime: UInt64) {
    this.depositSizes.getAndRequireEquals().has(size).assertTrue('not a deposit size');
    this.network.timestamp.requireBetween(depositTime, depositTime.add(UInt64.from(SLOT_MS)));
    const payer = AccountUpdate.createSigned(this.sender.getAndRequireSignature());
    payer.send({ to: this.address, amount: size });
    batchReducer.dispatch(VaultAction.deposit(commitment, size, depositTime));
  }

  /**
   * Leaving by agreement. Checks a mutual-close withdrawal proof and the zk edge's clearance of its
   * nullifier to its destination, then dispatches a close. Pays nothing: the reduce pays.
   */
  async mutualClose(proof: WithdrawalProof, clearance: Signature, nullifiers: NullifierSet) {
    proof.verify();
    const pub = proof.publicInput;
    pub.kind.assertEquals(WithdrawalKind.mutualClose, 'not a mutual close');

    const stateKey = this.stateKey.getAndRequireEquals();
    stateKey.isEmpty().assertFalse('vault not set up');
    pub.vault.equals(stateKey).assertTrue('not the vault state key');
    new RootRing(this.rootRing.getAndRequireEquals()).contains(pub.root).assertTrue('root not in the ring');
    // `pub.vault` is the stored state key, and unlike an unset one a valid point, so a close before
    // setup fails on the assertion above rather than inside the signature check.
    verifyClearance(clearance, { stateKey: pub.vault, nullifier: pub.nullifier, destination: pub.destination })
      .assertTrue('clearance not valid');

    const action = VaultAction.mutualClose(pub);
    this.network.timestamp.requireBetween(action.time, action.time.add(UInt64.from(CLOSE_WINDOW_MS)));

    nullifiers.root.assertEquals(this.nullifierRoot.getAndRequireEquals(), 'not the vault nullifier set');
    nullifiers.assertNotIncluded(pub.nullifier, 'nullifier spent');
    batchReducer.dispatch(action);
  }

  /**
   * Leaving without the zk edge. Checks an escape proof, landing between its `requestTime` and its
   * `validUntil`, whose current and next nullifiers are both unspent, then dispatches an escape. The
   * reduce consumes both nullifiers, records the escape and starts its challenge window. Pays nothing.
   */
  async escape(proof: WithdrawalProof, nullifiers: NullifierSet) {
    proof.verify();
    const pub = proof.publicInput;
    pub.kind.assertEquals(WithdrawalKind.escape, 'not an escape');

    const stateKey = this.stateKey.getAndRequireEquals();
    stateKey.isEmpty().assertFalse('vault not set up');
    pub.vault.equals(stateKey).assertTrue('not the vault state key');
    new RootRing(this.rootRing.getAndRequireEquals()).contains(pub.root).assertTrue('root not in the ring');

    const action = VaultAction.escape(pub);
    this.network.timestamp.requireBetween(action.time, action.validUntil);

    nullifiers.root.assertEquals(this.nullifierRoot.getAndRequireEquals(), 'not the vault nullifier set');
    nullifiers.assertNotIncluded(pub.nullifier, 'nullifier spent');
    nullifiers.assertNotIncluded(pub.nextNullifier, 'nullifier spent');
    batchReducer.dispatch(action);
  }

  /**
   * Permissionless, once the block time reaches the escape's deadline. Checks that `escape` is pending,
   * then dispatches a finalize; the reduce pays it.
   */
  async finalize(escape: PendingEscape, escapes: PendingEscapes) {
    escapes.root.assertEquals(this.pendingEscapesRoot.getAndRequireEquals(), 'not the vault pending escapes');
    escapes.getOption(escape.nullifier).orElse(0n).assertEquals(escape.hash(), 'no such pending escape');
    this.network.timestamp.requireBetween(escape.deadline, UInt64.MAXINT());
    batchReducer.dispatch(VaultAction.finalize(escape));
  }

  /**
   * Permissionless, before the escape's deadline. Cancels the pending `escape` with `evidence`, a request
   * proof at its next nullifier: the note's successor state opened an allowance, so the escape was from
   * a stale state. A subsidised proof defeats too (ADR 0001). The reduce finishes the escape without
   * paying; the deposit stays in the vault, and the note goes on from the state the zk edge signs after
   * that successor, since the escape consumed both its own and the successor's nullifier.
   */
  async defeat(escape: PendingEscape, evidence: RequestProof, escapes: PendingEscapes) {
    this.checkEvidence(evidence);
    evidence.publicInput.nullifier.assertEquals(escape.nextNullifier, "not the escape's next nullifier");
    this.checkChallengeable(escape, escapes);
    batchReducer.dispatch(VaultAction.defeat(escape));
  }

  /**
   * Permissionless, before the escape's deadline. Lifts the pending `escape`'s concession to
   * `min(claimed, b, balance)` with `evidence`, a request proof of tier `b` at its current nullifier
   * (ADR 0004: the challenger claims the allowance's recorded charge, or `b` if it never closed). Refused
   * unless that is more than the concession already is; a subsidised proof never raises (ADR 0001). The
   * reduce replaces the record.
   */
  async raise(escape: PendingEscape, evidence: RequestProof, claimed: UInt64, escapes: PendingEscapes) {
    this.checkEvidence(evidence);
    evidence.publicInput.nullifier.assertEquals(escape.nullifier, "not the escape's nullifier");
    this.checkChallengeable(escape, escapes);
    const action = VaultAction.raise(escape, evidence.publicInput, claimed);
    action.conceded.assertGreaterThan(escape.conceded, 'raise would not increase the concession');
    batchReducer.dispatch(action);
  }

  /**
   * Permissionless. Walks the next `count` notes (at most a batch) from the sweep cursor, each of which
   * must have expired by the block time, adds their sizes to the expired total, and dispatches a sweep of
   * that total; the reduce pays the treasury what the expired notes left (ADR 0005). Refused while
   * nothing has expired. A note counts only once a close proven before its expiry can no longer land,
   * at `expiry + CLOSE_WINDOW_MS`; an escape lands before its note's expiry. So every withdrawal of a
   * counted note was dispatched before the sweep, and the reduce applies it first.
   *
   * `notes` holds a batch: the walked notes in index order, padded with anything (`SweptNote.batch` builds one).
   * `now` is at most the block time. Deposit times may run up to a slot out of index order; a note
   * expiring later than the one after it holds that one back until it expires too.
   */
  async sweepExpired(count: UInt32, notes: Unconstrained<SweptNote[]>, now: UInt64) {
    this.treasury.getAndRequireEquals().isEmpty().assertFalse('vault not set up');
    this.network.timestamp.requireBetween(now, UInt64.MAXINT());
    const root = this.noteRoot.getAndRequireEquals();
    let cursor = this.sweepCursor.getAndRequireEquals();
    let expired = this.expiredTotal.getAndRequireEquals();
    const lapse = UInt64.from(policy.NOTE_LIFETIME_MS + CLOSE_WINDOW_MS);

    for (let i = 0; i < SWEEP_BATCH_SIZE; i++) {
      const walks = count.greaterThan(UInt32.from(i));
      const note = Provable.witness(SweptNote, () => notes.get()[i]);
      const leaf = depositLeaf(cursor, { commitment: note.commitment, size: note.size.value, depositTime: note.depositTime.value });
      const isNext = note.path.calculateIndex().equals(cursor).and(note.path.calculateRoot(leaf).equals(root));
      walks.not().or(isNext).assertTrue('not the note at the sweep cursor');
      // A note not walked may hold anything: it adds nothing, and must not overflow either.
      const depositTime = Provable.if(walks, UInt64, note.depositTime, UInt64.zero);
      walks.not().or(depositTime.add(lapse).lessThanOrEqual(now)).assertTrue('note not expired');
      expired = expired.add(Provable.if(walks, UInt64, note.size, UInt64.zero));
      cursor = Provable.if(walks, cursor.add(1), cursor);
    }

    expired.assertGreaterThan(UInt64.zero, 'nothing has expired');
    this.sweepCursor.set(cursor);
    this.expiredTotal.set(expired);
    batchReducer.dispatch(VaultAction.sweep(expired));
  }

  /**
   * A valid request proof under the vault's state key. Its root need not be in the ring: a challenger's
   * evidence may be older than the ring, and only the note's holder can prove at its nullifiers.
   */
  private checkEvidence(evidence: RequestProof) {
    evidence.verify();
    const stateKey = this.stateKey.getAndRequireEquals();
    stateKey.isEmpty().assertFalse('vault not set up');
    evidence.publicInput.vault.equals(stateKey).assertTrue('not the vault state key');
  }

  /** `escape` is pending as named, and the block time is before its deadline. */
  private checkChallengeable(escape: PendingEscape, escapes: PendingEscapes) {
    escapes.root.assertEquals(this.pendingEscapesRoot.getAndRequireEquals(), 'not the vault pending escapes');
    escapes.getOption(escape.nullifier).orElse(0n).assertEquals(escape.hash(), 'no such pending escape');
    // A recorded deadline is a full window after a reduce's block time, so never zero.
    this.network.timestamp.requireBetween(UInt64.zero, escape.deadline.sub(1));
  }

  /**
   * Permissionless. Folds up to a batch of pending actions:
   * - a deposit becomes the next note;
   * - a mutual close consumes its nullifier and pays `amount` to its destination and `size − amount` to
   *   the treasury;
   * - an escape consumes its current and next nullifiers and is recorded as pending, with a deadline a
   *   full challenge window after this reduce lands;
   * - a finalize finishes its pending escape and pays `amount − conceded` to the destination and the
   *   rest of `size` to the treasury;
   * - a defeat finishes its pending escape without paying;
   * - a raise replaces its pending escape with the raised record;
   * - a sweep pays the treasury `expired − claimed − swept`, or nothing if that is not positive, where
   *   `expired` is the sweep's and `claimed` and `swept` stand as of the actions before it (ADR 0005).
   * A close or escape with a nullifier already spent, in the set or earlier in the batch, and a finalize,
   * defeat or raise of an escape no longer pending as named, are skipped without paying and without failing.
   * So of a raise, a defeat and a finalize of one escape in one batch, only the first applies.
   * Each change to a pending escape is emitted as an `escape` event ({@link EscapeUpdate}).
   *
   * `now` pins the block time to within a slot after it.
   */
  async reduce(
    batch: VaultBatch, proof: VaultBatchProof, witnesses: Unconstrained<NoteWitness[]>, given: NullifierSet,
    givenEscapes: PendingEscapes, now: UInt64
  ) {
    // o1js may run a method more than once over the same argument; inserting into the caller's copy
    // would corrupt the next run.
    const nullifiers = given.clone();
    const escapes = givenEscapes.clone();
    escapes.root.assertEquals(this.pendingEscapesRoot.getAndRequireEquals(), 'not the vault pending escapes');
    this.network.timestamp.requireBetween(now, now.add(UInt64.from(SLOT_MS)));
    // The block time is at most `now + SLOT_MS`, so the window is never shorter than its full length.
    const deadline = now.add(UInt64.from(SLOT_MS)).add(this.challengeWindow.getAndRequireEquals());
    let root = this.noteRoot.getAndRequireEquals();
    let next = this.nextLeafIndex.getAndRequireEquals();
    const ring = new RootRing(this.rootRing.getAndRequireEquals());
    nullifiers.root.assertEquals(this.nullifierRoot.getAndRequireEquals(), 'not the vault nullifier set');
    const treasury = this.treasury.getAndRequireEquals();
    let claimed = this.claimedTotal.getAndRequireEquals();
    let swept = this.sweptTotal.getAndRequireEquals();
    let changed = Bool(false);

    batchReducer.processBatch({ batch, proof }, (action, isDummy, i) => {
      const isDeposit = isDummy.not().and(action.kind.equals(ActionKind.deposit));
      const isClose = isDummy.not().and(action.kind.equals(ActionKind.mutualClose));
      const isEscape = isDummy.not().and(action.kind.equals(ActionKind.escape));
      const isFinalize = isDummy.not().and(action.kind.equals(ActionKind.finalize));
      const isDefeat = isDummy.not().and(action.kind.equals(ActionKind.defeat));
      const isRaise = isDummy.not().and(action.kind.equals(ActionKind.raise));
      const isSweep = isDummy.not().and(action.kind.equals(ActionKind.sweep));

      const witness = Provable.witness(NoteWitness, () => witnesses.get()[i]);
      // The slot at `next` must be empty under the current root.
      witness.calculateIndex().assertEquals(next);
      const noteLeaf = depositLeaf(next, {
        commitment: action.commitment, size: action.size.value, depositTime: action.time.value,
      });
      witness.calculateRoot(Field(0)).assertEquals(root);
      root = Provable.if(isDeposit, witness.calculateRoot(noteLeaf), root);
      next = Provable.if(isDeposit, next.add(1), next);
      changed = changed.or(isDeposit);

      // Kinds without a nullifier look up 1: the sets cannot look up 0, since no key is below it.
      const spends = isClose.or(isEscape);
      const current = Provable.if(spends, action.nullifier, Field(1));
      const following = Provable.if(isEscape, action.nextNullifier, Field(1));
      const currentFresh = nullifiers.isIncluded(current).not();
      const nextFresh = nullifiers.isIncluded(following).not();
      const closes = isClose.and(currentFresh);
      const recorded = isEscape.and(currentFresh).and(nextFresh);
      nullifiers.setIf(closes.or(recorded), current, Field(1));
      nullifiers.setIf(recorded, following, Field(1));

      // An escape records its pending escape. A finalize or a defeat finishes the one it names, and a raise
      // replaces it with the raised record, each only if that escape is still pending as named: a finalize
      // or a defeat names the record itself, a raise names it by hash.
      const record = action.pendingEscape(Provable.if(isEscape, UInt64, deadline, action.time));
      const recordHash = record.hash();
      const key = Provable.if(isEscape.or(isFinalize).or(isDefeat).or(isRaise), action.nullifier, Field(1));
      const named = Provable.if(isRaise, action.commitment, recordHash);
      const stands = escapes.getOption(key).orElse(0n).equals(named);
      const finalizes = isFinalize.and(stands);
      const writes = recorded.or(isRaise.and(stands));
      const defeats = isDefeat.and(stands);
      const updates = writes.or(finalizes).or(defeats);
      escapes.setIf(updates, key, Provable.if(writes, recordHash, Field(0)));
      this.emitEventIf(updates, 'escape', new EscapeUpdate({ pending: writes, record }));

      // A close or a recorded escape claims its note's size, and a defeat gives it back; a finalize pays
      // what its escape already claimed.
      claimed = claimed.add(Provable.if(closes.or(recorded), UInt64, action.size, UInt64.zero));
      claimed = claimed.sub(Provable.if(defeats, UInt64, action.size, UInt64.zero));

      // A sweep pays what the expired notes left: the expired total less what is claimed and already swept.
      const owed = claimed.add(swept);
      const left = Provable.if(action.size.greaterThan(owed), UInt64, action.size, owed).sub(owed);
      const sweeps = Provable.if(isSweep, UInt64, left, UInt64.zero);
      swept = swept.add(sweeps);

      // A close pays its balance and a finalize its balance less the concession, each the rest of the size
      // to the treasury; a sweep pays the treasury alone; other kinds pay nothing.
      const pays = closes.or(finalizes);
      const payout = Provable.if(isFinalize, UInt64, record.payout(), action.amount);
      this.payIf(pays, action.destination, payout);
      this.payIf(pays.or(isSweep), treasury, Provable.if(isSweep, UInt64, sweeps, action.size.sub(payout)));
    });

    this.noteRoot.set(root);
    this.nextLeafIndex.set(next);
    this.rootRing.set(new RootRing(Provable.if(changed, RootRing, ring.push(root), ring)));
    this.nullifierRoot.set(nullifiers.root);
    this.pendingEscapesRoot.set(escapes.root);
    this.claimedTotal.set(claimed);
    this.sweptTotal.set(swept);
  }

  /** A circuit sends a fixed number of updates, so a skipped or zero payout is a zero send to the vault itself. */
  private payIf(condition: Bool, to: PublicKey, amount: UInt64) {
    const pay = condition.and(amount.equals(UInt64.zero).not());
    this.send({
      to: Provable.if(pay, PublicKey, to, this.address),
      amount: Provable.if(pay, UInt64, amount, UInt64.zero),
    });
  }
}

// declareMethods' argument type is looser than the types it accepts.
declareMethods(Vault, {
  setup: [PublicKey, PublicKey],
  deposit: [Field, UInt64, UInt64],
  mutualClose: [WithdrawalProof, Signature, NullifierSet],
  escape: [WithdrawalProof, NullifierSet],
  finalize: [PendingEscape, PendingEscapes],
  defeat: [PendingEscape, RequestProof, PendingEscapes],
  raise: [PendingEscape, RequestProof, UInt64, PendingEscapes],
  sweepExpired: [UInt32, Unconstrained.provable, UInt64],
  reduce: [VaultBatch, VaultBatchProof, Unconstrained.provable, NullifierSet, PendingEscapes, UInt64],
} as Record<string, any[]>);

declareState(Vault, {
  actionState: Field,
  actionStack: Field,
  noteRoot: Field,
  nextLeafIndex: Field,
  rootRing: RootRing,
  creationTime: UInt64,
  depositSizes: DepositSizes,
  noteLifetime: UInt64,
  challengeWindow: UInt64,
  nullifierRoot: Field,
  stateKey: PublicKey,
  treasury: PublicKey,
  pendingEscapesRoot: Field,
  sweepCursor: Field,
  expiredTotal: UInt64,
  claimedTotal: UInt64,
  sweptTotal: UInt64,
});

batchReducer.setContractClass(Vault);
