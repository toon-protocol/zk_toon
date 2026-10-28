// The note tree: a Merkle tree of leaves, mirrored off chain so tests and later issues can build witnesses.
import { Field, MerkleTree, MerkleWitness } from 'o1js';
import { leaf } from './primitives.js';
import { expiryOfField } from './policy.js';

export const NOTE_TREE_HEIGHT = 20;
export class NoteWitness extends MerkleWitness(NOTE_TREE_HEIGHT) {}

/** A deposit as dispatched: the payer's secret commitment, the size paid and the named deposit time. */
export interface DepositLike {
  commitment: Field;
  size: Field;
  depositTime: Field;
}

/** The leaf a deposit becomes at `index`; the expiry is `expiryOf(depositTime)` of the policy. */
export const depositLeaf = (index: Field, d: DepositLike) =>
  leaf(index, d.commitment, d.size, d.depositTime, expiryOfField(d.depositTime));

export const emptyNoteRoot = () => new MerkleTree(NOTE_TREE_HEIGHT).getRoot();

export class NoteTree {
  private tree = new MerkleTree(NOTE_TREE_HEIGHT);
  private count = 0n;

  get root(): Field {
    return this.tree.getRoot();
  }
  get nextIndex(): bigint {
    return this.count;
  }
  /** Adds a deposit at the next index, as a reduce does; returns the index. */
  append(d: DepositLike): bigint {
    const index = this.count++;
    this.tree.setLeaf(index, depositLeaf(Field(index), d));
    return index;
  }
  leafAt(index: bigint): Field {
    return this.tree.getNode(0, index);
  }
  witness(index: bigint): NoteWitness {
    return new NoteWitness(this.tree.getWitness(index));
  }
}

/**
 * The witnesses one reduce batch needs: for each action, the empty slot a deposit fills, in order; an action
 * that is not a deposit (`undefined`) leaves the tree as it is. Appends the
 * deposits to `tree` as the reduce will, and pads to `batchSize` with the next empty slot's witness: the
 * reduce checks every slot, dummies included, against an empty slot at the next index.
 */
export function reduceWitnesses(
  tree: NoteTree, deposits: (DepositLike | undefined)[], batchSize: number
): NoteWitness[] {
  const out = deposits.map((d) => {
    const w = tree.witness(tree.nextIndex);
    if (d) tree.append(d);
    return w;
  });
  while (out.length < batchSize) out.push(tree.witness(tree.nextIndex));
  return out;
}
