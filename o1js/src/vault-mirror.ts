// The vault's shared state, mirrored off chain: the note tree, the nullifier set and the pending escapes,
// advanced as a reduce advances them. A reduce caller (and the tests) builds each reduce's inputs from it;
// a finalize caller and a challenger read pending escapes from it, and it follows their raises and defeats.
import { Field, UInt64 } from 'o1js';
import { NoteTree, NoteWitness } from './note-tree.js';
import { CHALLENGE_WINDOW_MS } from './policy.js';
import {
  ActionKind, NullifierSet, PendingEscape, PendingEscapes, REDUCE_BATCH_SIZE, SLOT_MS, VaultAction,
} from './vault.js';

export class VaultMirror {
  readonly tree = new NoteTree();
  nullifiers = new NullifierSet();
  escapes = new PendingEscapes();
  /** Dispatched actions not yet reduced, oldest first. */
  private pending: VaultAction[] = [];
  /** Note indices by secret commitment. */
  private indices = new Map<bigint, bigint>();
  /** Pending escapes by current nullifier. */
  private records = new Map<bigint, PendingEscape>();

  /** Records an action the vault dispatched. */
  dispatched(action: VaultAction) {
    this.pending.push(action);
  }

  indexOf(commitment: Field): bigint {
    const index = this.indices.get(commitment.toBigInt());
    if (index === undefined) throw Error('no such note in the tree');
    return index;
  }

  /** The escape pending at `nullifier`, its escaping state's nullifier, if any. */
  pendingEscape(nullifier: Field): PendingEscape | undefined {
    return this.records.get(nullifier.toBigInt());
  }

  /**
   * The inputs of the next reduce, which folds the oldest `batchSize` pending actions at block time
   * `now` (the reduce's own argument): the nullifier set and pending escapes as they stand, and for each
   * action the empty note slot it checks against, padded to `batchSize`. Advances the mirror past that
   * batch, as the reduce will.
   */
  nextReduce(now: bigint, batchSize = REDUCE_BATCH_SIZE) {
    const nullifiers = this.nullifiers.clone();
    const escapes = this.escapes.clone();
    const deadline = UInt64.from(now + SLOT_MS + CHALLENGE_WINDOW_MS);
    const spent = (n: Field) => this.nullifiers.isIncluded(n).toBoolean();
    const witnesses: NoteWitness[] = this.pending.splice(0, batchSize).map((a) => {
      const w = this.tree.witness(this.tree.nextIndex);
      const kind = Number(a.kind.toBigInt());
      if (kind === ActionKind.deposit) {
        const index = this.tree.append({ commitment: a.commitment, size: a.size.value, depositTime: a.time.value });
        this.indices.set(a.commitment.toBigInt(), index);
      } else if (kind === ActionKind.mutualClose && !spent(a.nullifier)) {
        this.nullifiers.insert(a.nullifier, 1n);
      } else if (kind === ActionKind.escape && !spent(a.nullifier) && !spent(a.nextNullifier)) {
        this.nullifiers.insert(a.nullifier, 1n);
        this.nullifiers.insert(a.nextNullifier, 1n);
        const record = a.pendingEscape(deadline);
        this.escapes.insert(a.nullifier, record.hash());
        this.records.set(a.nullifier.toBigInt(), record);
      } else if (kind === ActionKind.finalize || kind === ActionKind.defeat || kind === ActionKind.raise) {
        // A raise names the record it replaces by hash; a finalize or a defeat names the record itself.
        const record = a.pendingEscape(a.time);
        const named = kind === ActionKind.raise ? a.commitment : record.hash();
        if (this.escapes.getOption(a.nullifier).orElse(0n).equals(named).toBoolean()) {
          if (kind === ActionKind.raise) {
            this.escapes.set(a.nullifier, record.hash());
            this.records.set(a.nullifier.toBigInt(), record);
          } else {
            this.escapes.set(a.nullifier, 0n);
            this.records.delete(a.nullifier.toBigInt());
          }
        }
      }
      return w;
    });
    while (witnesses.length < batchSize) witnesses.push(this.tree.witness(this.tree.nextIndex));
    return { witnesses, nullifiers, escapes };
  }
}
