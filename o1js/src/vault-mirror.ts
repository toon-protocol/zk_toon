// The vault's shared state, mirrored off chain: the note tree and the nullifier set, advanced as a reduce
// advances them. A reduce caller (and the tests) builds each reduce's inputs from it.
import { Field } from 'o1js';
import { NoteTree, NoteWitness } from './note-tree.js';
import { ActionKind, NullifierSet, REDUCE_BATCH_SIZE, VaultAction } from './vault.js';

export class VaultMirror {
  readonly tree = new NoteTree();
  nullifiers = new NullifierSet();
  /** Dispatched actions not yet reduced, oldest first. */
  private pending: VaultAction[] = [];
  /** Note indices by secret commitment. */
  private indices = new Map<bigint, bigint>();

  /** Records an action the vault dispatched. */
  dispatched(action: VaultAction) {
    this.pending.push(action);
  }

  indexOf(commitment: Field): bigint {
    const index = this.indices.get(commitment.toBigInt());
    if (index === undefined) throw Error('no such note in the tree');
    return index;
  }

  /**
   * The inputs of the next reduce, which folds the oldest `batchSize` pending actions: the nullifier set
   * as it stands, and for each action the empty note slot it checks against, padded to `batchSize`.
   * Advances the mirror past that batch, as the reduce will.
   */
  nextReduce(batchSize = REDUCE_BATCH_SIZE): { witnesses: NoteWitness[]; nullifiers: NullifierSet } {
    const nullifiers = this.nullifiers.clone();
    const witnesses = this.pending.splice(0, batchSize).map((a) => {
      const w = this.tree.witness(this.tree.nextIndex);
      const kind = Number(a.kind.toBigInt());
      if (kind === ActionKind.deposit) {
        const index = this.tree.append({ commitment: a.commitment, size: a.size.value, depositTime: a.time.value });
        this.indices.set(a.commitment.toBigInt(), index);
      } else if (kind === ActionKind.mutualClose && !this.nullifiers.isIncluded(a.nullifier).toBoolean()) {
        this.nullifiers.insert(a.nullifier, 1n);
      }
      return w;
    });
    while (witnesses.length < batchSize) witnesses.push(this.tree.witness(this.tree.nextIndex));
    return { witnesses, nullifiers };
  }
}
