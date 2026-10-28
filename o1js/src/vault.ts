// The vault zkApp. A deposit moves a fixed size into the vault and dispatches an action; a mutual close
// checks a withdrawal proof and the zk edge's clearance and dispatches an action. A permissionless reduce
// folds every pending action in: deposits into the note tree, closes into the nullifier set and payouts.
// A deposit is a note only once reduced, and a close is paid only at the reduce (ADR 0002, "A mutual
// close pays at the reduce, through the one action stream").
import {
  AccountUpdate, Bool, Experimental, Field, IndexedMerkleMap, Provable, PublicKey, Signature, SmartContract,
  State, Struct, UInt64, Unconstrained, declareMethods, declareState,
} from 'o1js';
import * as policy from './policy.js';
import { verifyClearance } from './clearance.js';
import { NoteWitness, depositLeaf, emptyNoteRoot } from './note-tree.js';
import { WithdrawalKind, WithdrawalProof, type WithdrawalPublic } from './withdrawal.js';

/** How many recent note-tree roots the vault remembers. */
export const ROOT_RING_LENGTH = 8;
/** Mesa slots are 90 s. */
export const SLOT_MS = 90_000n;
/**
 * Actions folded per reduce. A reduce sends two account updates per action (a close's two payouts),
 * so a full batch is 10 unsigned updates: 5 pairs, plus the fee payer and the vault, 7 of Mina's 16
 * segments per transaction.
 */
export const REDUCE_BATCH_SIZE = 5;
/** How long after its `requestTime` a mutual close may land: the connector's request-time window. */
export const CLOSE_WINDOW_MS = policy.REQUEST_MAX_AGE_MS;
/** The nullifier set holds up to 2^(height − 1) nullifiers. */
export const NULLIFIER_SET_HEIGHT = 32;

/** The consumed nullifiers. The vault stores only the root: a reduce inserts, a close proves absence. */
export class NullifierSet extends IndexedMerkleMap(NULLIFIER_SET_HEIGHT) {}

/** The kinds of the vault's one action stream. 0 is never dispatched; #9–#11 add theirs. */
export enum ActionKind {
  deposit = 1,
  mutualClose = 2,
}

/**
 * The vault's one fixed-width action. Each kind uses some fields and leaves the rest zero: a deposit
 * `commitment`, `size` and `time` (its deposit time); a mutual close `nullifier`, `amount`, `size`,
 * `destination` and `time` (its request time). `nextNullifier` and `validUntil` are for escapes (#9).
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
}) {
  static none(): VaultAction {
    return new VaultAction({
      kind: Field(0), commitment: Field(0), nullifier: Field(0), nextNullifier: Field(0), amount: UInt64.zero,
      size: UInt64.zero, time: UInt64.zero, validUntil: UInt64.zero, destination: PublicKey.empty(),
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
  // State fields in use: 2 (batch reducer) + 1 + 1 + (8 + 1) + 1 + 3 + 1 + 1 + 1 + 2 + 2 = 24 of Mesa's 32.
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
   * Permissionless. Folds up to a batch of pending actions: a deposit becomes the next note; a mutual
   * close consumes its nullifier and pays `amount` to its destination and `size − amount` to the
   * treasury. A close whose nullifier is already spent, in the set or earlier in the batch, is skipped
   * without paying and without failing.
   */
  async reduce(
    batch: VaultBatch, proof: VaultBatchProof, witnesses: Unconstrained<NoteWitness[]>, given: NullifierSet
  ) {
    // o1js may run a method more than once over the same argument; inserting into the caller's copy
    // would corrupt the next run.
    const nullifiers = given.clone();
    let root = this.noteRoot.getAndRequireEquals();
    let next = this.nextLeafIndex.getAndRequireEquals();
    const ring = new RootRing(this.rootRing.getAndRequireEquals());
    nullifiers.root.assertEquals(this.nullifierRoot.getAndRequireEquals(), 'not the vault nullifier set');
    const treasury = this.treasury.getAndRequireEquals();
    let changed = Bool(false);

    batchReducer.processBatch({ batch, proof }, (action, isDummy, i) => {
      const isDeposit = isDummy.not().and(action.kind.equals(ActionKind.deposit));
      const isClose = isDummy.not().and(action.kind.equals(ActionKind.mutualClose));

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

      // Other kinds carry nullifier 0, which the set cannot look up (no key is below it): they look up 1.
      const nullifier = Provable.if(isClose, action.nullifier, Field(1));
      const pays = isClose.and(nullifiers.isIncluded(nullifier).not());
      nullifiers.setIf(pays, nullifier, Field(1));
      // A close's amount never exceeds its size: the withdrawal circuit proves it. Other kinds pay nothing.
      this.payIf(pays, action.destination, action.amount);
      this.payIf(pays, treasury, action.size.sub(action.amount));
    });

    this.noteRoot.set(root);
    this.nextLeafIndex.set(next);
    this.rootRing.set(new RootRing(Provable.if(changed, RootRing, ring.push(root), ring)));
    this.nullifierRoot.set(nullifiers.root);
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
  reduce: [VaultBatch, VaultBatchProof, Unconstrained.provable, NullifierSet],
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
});

batchReducer.setContractClass(Vault);
