// The vault zkApp. A deposit moves a fixed size into the vault and dispatches an action; a mutual close
// dispatches one too. A permissionless reduce handles every action: it folds deposits into the note tree,
// and pays mutual closes after inserting their nullifiers (ADR 0002). A deposit is a note only once reduced.
import {
  AccountUpdate, Bool, Experimental, Field, IndexedMerkleMap, Provable, PublicKey, Signature, SmartContract, State, Struct,
  UInt64, Unconstrained, declareMethods, declareState,
} from 'o1js';
import * as policy from './policy.js';
import { NoteWitness, depositLeaf, emptyNoteRoot } from './note-tree.js';
import { verifyClearance } from './clearance.js';
import { tagToBigint } from './primitives.js';
import { KIND_MUTUAL_CLOSE, WithdrawalProof } from './withdrawal.js';

/** How many recent note-tree roots the vault remembers. */
export const ROOT_RING_LENGTH = 8;
/** Mesa slots are 90 s. */
export const SLOT_MS = 90_000n;
/** Actions handled per reduce. A close pays up to two account updates, so this is bounded by Mina's limit per transaction. */
export const REDUCE_BATCH_SIZE = 5;
/** A mutual close must land within this long after its request time. */
export const CLOSE_WINDOW_MS = 600_000n;
/** The nullifier set's height: room for about 2^19 spent states. */
export const NULLIFIER_TREE_HEIGHT = 20;

/** The nullifier set: every spent state's nullifier, each mapped to 1. */
export class NullifierMap extends IndexedMerkleMap(NULLIFIER_TREE_HEIGHT) {}

/** The kinds of the vault's one action stream. Zero is the dummy the batch reducer pads with. */
export const ACTION_DEPOSIT = 1;
export const ACTION_MUTUAL_CLOSE = 2;
// 3 is reserved for escape (#9).

/**
 * The vault's one fixed-width action. Which fields are read depends on `kind`; the rest are zero. The
 * width leaves room for the escape fields: both nullifiers, `amount`, `size`, `destination`, `validUntil`.
 */
export class VaultAction extends Struct({
  kind: Field,
  commitment: Field,
  size: UInt64,
  depositTime: UInt64,
  nullifier: Field,
  nextNullifier: Field,
  amount: UInt64,
  destination: PublicKey,
  validUntil: UInt64,
  requestTime: UInt64,
}) {
  static deposit(commitment: Field, size: UInt64, depositTime: UInt64) {
    return new VaultAction({ ...VaultAction.empty(), kind: Field(ACTION_DEPOSIT), commitment, size, depositTime });
  }
  static mutualClose(nullifier: Field, amount: UInt64, size: UInt64, destination: PublicKey, requestTime: UInt64) {
    return new VaultAction({
      ...VaultAction.empty(), kind: Field(ACTION_MUTUAL_CLOSE), nullifier, amount, size, destination, requestTime,
    });
  }
}

const SETUP_TAG = 'toon.zk.vault-setup.v1';
/** What the vault account signs to set the state key and treasury, once. */
export const setupFields = (vault: PublicKey, stateKey: PublicKey, treasury: PublicKey) => [
  Field(tagToBigint(SETUP_TAG)),
  vault.x, vault.isOdd.toField(), stateKey.x, stateKey.isOdd.toField(), treasury.x, treasury.isOdd.toField(),
];

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
export class ActionBatch extends batchReducer.Batch {}
export class ActionBatchProof extends batchReducer.BatchProof {}

/** Precondition on a payee: its account exists, so a payout to it opens no account and cannot fail for want of the fee. */
function requireAccountExists(address: PublicKey) {
  AccountUpdate.create(address).account.isNew.requireEquals(Bool(false));
}

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
  nullifierRoot = State<Field>();
  /** The zk edge's key, which signs states and clearances. Empty (x = 0) until `setup`. */
  stateKey = State<PublicKey>();
  /** Receives what a closed note's balance leaves of its deposit. */
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
    this.nullifierRoot.set(new NullifierMap().root);
    this.stateKey.set(PublicKey.empty());
    this.treasury.set(PublicKey.empty());
  }

  /**
   * One-time: records the state key and the treasury. The vault account must have signed them, and it is
   * refused once a state key is set.
   */
  async setup(stateKey: PublicKey, treasury: PublicKey, signature: Signature) {
    this.stateKey.getAndRequireEquals().x.assertEquals(0, 'already set up');
    stateKey.x.equals(0).assertFalse('no state key');
    signature.verify(this.address, setupFields(this.address, stateKey, treasury)).assertTrue('not signed by the vault');
    requireAccountExists(treasury);
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
   * A mutual close: the zk edge's clearance for one nullifier and one destination, and a withdrawal proof
   * for a state not yet spent. It pays nothing; the reduce does (ADR 0002). `nullifiers` is the set as
   * stored, which shows the nullifier absent.
   */
  async mutualClose(proof: WithdrawalProof, clearance: Signature, nullifiers: NullifierMap) {
    proof.verify();
    const pub = proof.publicInput;
    pub.kind.assertEquals(KIND_MUTUAL_CLOSE, 'not a mutual close');

    const stateKey = this.stateKey.getAndRequireEquals();
    const isSet = stateKey.x.equals(0).not();
    isSet.assertTrue('setup has not run');
    pub.vault.equals(stateKey).assertTrue('not the state key');
    this.rootRing.getAndRequireEquals().contains(pub.root).assertTrue('root not in the ring');
    // Before setup the state key is no curve point, which a signature check cannot take; the close fails above.
    const signer = Provable.if(isSet, PublicKey, stateKey, this.address);
    verifyClearance(clearance, { stateKey: signer, nullifier: pub.nullifier, destination: pub.destination })
      .assertTrue('bad clearance');

    const requestTime = UInt64.Unsafe.fromField(pub.requestTime);
    this.network.timestamp.requireBetween(requestTime, requestTime.add(UInt64.from(CLOSE_WINDOW_MS)));

    // A payout to an account that does not exist would fail the reduce, and stall every action queued behind it.
    requireAccountExists(pub.destination);

    nullifiers.root.assertEquals(this.nullifierRoot.getAndRequireEquals());
    nullifiers.assertNotIncluded(pub.nullifier, 'nullifier spent');

    batchReducer.dispatch(
      VaultAction.mutualClose(
        pub.nullifier, UInt64.Unsafe.fromField(pub.amount), UInt64.Unsafe.fromField(pub.size),
        pub.destination, requestTime
      )
    );
  }

  /**
   * Permissionless. Folds up to a batch of pending actions: deposits into the note tree, and for each
   * mutual close its nullifier into the nullifier set and its payout. A close whose nullifier is already
   * in the set, or came earlier in the batch, is skipped without paying and without failing.
   */
  async reduce(
    batch: ActionBatch, proof: ActionBatchProof, witnesses: Unconstrained<NoteWitness[]>, nullifiers: NullifierMap
  ) {
    let root = this.noteRoot.getAndRequireEquals();
    let next = this.nextLeafIndex.getAndRequireEquals();
    const ring = new RootRing(this.rootRing.getAndRequireEquals());
    const treasury = this.treasury.getAndRequireEquals();
    // The argument stays as given: a method may run more than once, each time on the same argument.
    const set = nullifiers.clone();
    set.root.assertEquals(this.nullifierRoot.getAndRequireEquals());
    let changed = Bool(false);

    batchReducer.processBatch({ batch, proof }, (action, isDummy, i) => {
      const isDeposit = isDummy.not().and(action.kind.equals(ACTION_DEPOSIT));
      const isClose = isDummy.not().and(action.kind.equals(ACTION_MUTUAL_CLOSE));

      const witness = Provable.witness(NoteWitness, () => witnesses.get()[i]);
      // The slot at `next` must be empty under the current root.
      witness.calculateIndex().assertEquals(next);
      const noteLeaf = depositLeaf(next, {
        commitment: action.commitment, size: action.size.value, depositTime: action.depositTime.value,
      });
      witness.calculateRoot(Field(0)).assertEquals(root);
      root = Provable.if(isDeposit, witness.calculateRoot(noteLeaf), root);
      next = Provable.if(isDeposit, next.add(1), next);
      changed = changed.or(isDeposit);

      // The set takes the nullifier only for a close. Other lanes insert a placeholder key into a copy that
      // is then dropped; the map's own `setIf` would instead touch its last leaf through the zero key.
      const attempt = set.clone();
      const previous = attempt.set(Provable.if(isClose, action.nullifier, Field(1)), Field(1));
      set.overwriteIf(isClose, attempt);
      // Where a lane pays nothing, its zero-amount update goes to the vault itself.
      const pay = isClose.and(previous.isSome.not());
      const toDestination = pay.and(action.amount.greaterThan(UInt64.zero));
      const rest = Provable.if(pay, action.size.sub(action.amount), UInt64.zero);
      const toTreasury = pay.and(rest.greaterThan(UInt64.zero));
      this.send({
        to: Provable.if(toDestination, PublicKey, action.destination, this.address),
        amount: Provable.if(toDestination, UInt64, action.amount, UInt64.zero),
      });
      this.send({
        to: Provable.if(toTreasury, PublicKey, treasury, this.address),
        amount: Provable.if(toTreasury, UInt64, rest, UInt64.zero),
      });
    });

    this.noteRoot.set(root);
    this.nextLeafIndex.set(next);
    this.nullifierRoot.set(set.root);
    this.rootRing.set(new RootRing(Provable.if(changed, RootRing, ring.push(root), ring)));
  }
}

// declareMethods' argument type is looser than the types it accepts.
declareMethods(Vault, {
  setup: [PublicKey, PublicKey, Signature],
  deposit: [Field, UInt64, UInt64],
  mutualClose: [WithdrawalProof, Signature, NullifierMap],
  reduce: [ActionBatch, ActionBatchProof, Unconstrained.provable, NullifierMap],
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
