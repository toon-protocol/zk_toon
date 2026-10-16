// The vault zkApp's deposit path. A deposit moves a fixed size into the vault and dispatches an action;
// a permissionless reduce folds pending deposits into the note tree. A deposit is a note only once reduced.
import {
  AccountUpdate, Bool, Experimental, Field, Provable, SmartContract, State, Struct,
  UInt64, Unconstrained, declareMethods, declareState,
} from 'o1js';
import * as policy from './policy.js';
import { NOTE_TREE_HEIGHT, NoteWitness, depositLeaf, emptyNoteRoot } from './note-tree.js';

export { NOTE_TREE_HEIGHT };
/** How many recent note-tree roots the vault remembers. */
export const ROOT_RING_LENGTH = 8;
/** Mesa slots are 90 s. */
export const SLOT_MS = 90_000n;
/** Deposits folded per reduce. */
export const REDUCE_BATCH_SIZE = 5;

export class Deposit extends Struct({ commitment: Field, size: UInt64, depositTime: UInt64 }) {}

/** The accepted deposit sizes, as on-chain state. */
export class DepositSizes extends Struct({ a: UInt64, b: UInt64, c: UInt64 }) {
  static fromPolicy() {
    const [a, b, c] = policy.DEPOSIT_SIZES.map((s) => UInt64.from(s));
    return new DepositSizes({ a, b, c });
  }
  has(size: UInt64): Bool {
    return size.equals(this.a).or(size.equals(this.b)).or(size.equals(this.c));
  }
}

/** The latest note-tree roots; a slot is zero until written. `head` is the next slot to overwrite. */
export class RootRing extends Struct({ roots: Provable.Array(Field, ROOT_RING_LENGTH) }) {
  static empty() {
    return new RootRing({ roots: Array.from({ length: ROOT_RING_LENGTH }, () => Field(0)) });
  }
  contains(root: Field): Bool {
    // Empty slots hold zero, which is no root.
    return this.roots.reduce((acc, r) => acc.or(r.equals(root)), Bool(false)).and(root.equals(0).not());
  }
  push(head: Field, root: Field): RootRing {
    return new RootRing({ roots: this.roots.map((r, i) => Provable.if(head.equals(i), root, r)) });
  }
}

const { BatchReducer } = Experimental;
export const batchReducer = new BatchReducer({ actionType: Deposit, batchSize: REDUCE_BATCH_SIZE });
export class DepositBatch extends batchReducer.Batch {}
export class DepositBatchProof extends batchReducer.BatchProof {}

export class Vault extends SmartContract {
  // State fields in use: 2 (batch reducer) + 1 + 1 + 8 + 1 + 1 + 3 + 1 + 1 = 19 of Mesa's 32.
  actionState = State<Field>();
  actionStack = State<Field>();
  noteRoot = State<Field>();
  nextLeafIndex = State<Field>();
  rootRing = State<RootRing>();
  ringHead = State<Field>();
  creationTime = State<UInt64>();
  depositSizes = State<DepositSizes>();
  noteLifetime = State<UInt64>();
  challengeWindow = State<UInt64>();

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
    this.ringHead.set(Field(0));
  }

  async deposit(commitment: Field, size: UInt64, depositTime: UInt64) {
    this.depositSizes.getAndRequireEquals().has(size).assertTrue('not a deposit size');
    this.network.timestamp.requireBetween(depositTime, depositTime.add(UInt64.from(SLOT_MS)));
    const payer = AccountUpdate.createSigned(this.sender.getAndRequireSignature());
    payer.send({ to: this.address, amount: size });
    batchReducer.dispatch(new Deposit({ commitment, size, depositTime }));
  }

  /** Permissionless. Folds up to a batch of pending deposits into the note tree, then records the new root. */
  async reduce(batch: DepositBatch, proof: DepositBatchProof, witnesses: Unconstrained<NoteWitness[]>) {
    let root = this.noteRoot.getAndRequireEquals();
    let next = this.nextLeafIndex.getAndRequireEquals();
    const ring = new RootRing(this.rootRing.getAndRequireEquals());
    const head = this.ringHead.getAndRequireEquals();
    let changed = Bool(false);

    batchReducer.processBatch({ batch, proof }, (deposit, isDummy, i) => {
      const w = Provable.witness(NoteWitness, () => witnesses.get()[i]);
      // The slot at `next` must be empty under the current root.
      w.calculateIndex().assertEquals(next);
      const l = depositLeaf(next, {
        commitment: deposit.commitment, size: deposit.size.value, depositTime: deposit.depositTime.value,
      });
      w.calculateRoot(Field(0)).assertEquals(root);
      root = Provable.if(isDummy, root, w.calculateRoot(l));
      next = Provable.if(isDummy, next, next.add(1));
      changed = changed.or(isDummy.not());
    });

    this.noteRoot.set(root);
    this.nextLeafIndex.set(next);
    this.rootRing.set(new RootRing(Provable.if(changed, RootRing, ring.push(head, root), ring)));
    const advanced = head.add(1);
    const wrapped = Provable.if(advanced.equals(ROOT_RING_LENGTH), Field(0), advanced);
    this.ringHead.set(Provable.if(changed, wrapped, head));
  }
}

// declareMethods' argument type is looser than the types it accepts.
declareMethods(Vault, {
  deposit: [Field, UInt64, UInt64],
  reduce: [DepositBatch, DepositBatchProof, Unconstrained.provable],
} as Record<string, any[]>);

declareState(Vault, {
  actionState: Field,
  actionStack: Field,
  noteRoot: Field,
  nextLeafIndex: Field,
  rootRing: RootRing,
  ringHead: Field,
  creationTime: UInt64,
  depositSizes: DepositSizes,
  noteLifetime: UInt64,
  challengeWindow: UInt64,
});

batchReducer.setContractClass(Vault);
