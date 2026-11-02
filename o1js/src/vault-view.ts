// The vault's off-chain state as the transaction builder needs it, read from the chain: the note tree and
// the nullifier set, rebuilt by replaying the actions the vault has reduced, and the pending escapes,
// rebuilt by replaying its `escape` events. Also the local chain's keeper,
// which reduces a vault's pending actions as a keeper would.
import { Bool, Experimental, Field, Mina, PublicKey, TokenId, UInt64, Unconstrained } from 'o1js';
import { EscapeUpdate, PendingEscape, PendingEscapes, Vault, VaultAction, VaultBatchProof, batchReducer, REDUCE_BATCH_SIZE } from './vault.js';
import { VaultMirror } from './vault-mirror.js';

type Account = Awaited<ReturnType<typeof Mina.LocalBlockchain>>['testAccounts'][number];

/** Every action `vault` has dispatched, oldest first, up to `endActionState` when given. */
export async function actions(vault: PublicKey, endActionState?: Field): Promise<VaultAction[]> {
  // Nothing is reduced yet, and an archive asked for actions up to the empty state may answer with all of them.
  if (endActionState?.equals(Experimental.BatchReducer.initialActionState).toBoolean()) return [];
  const lists = await Mina.fetchActions(vault, endActionState ? { endActionState } : undefined);
  if ('error' in lists) throw Error(`could not fetch the vault's actions: ${JSON.stringify(lists.error)}`);
  return lists.flatMap((l) => l.actions.map((a) => new VaultAction(VaultAction.fromFields(a.map((f) => Field(f))))));
}

/**
 * The note tree and nullifier set of `vault`, as of its last reduce, checked against its on-chain roots.
 * Pending escapes are not rebuilt: their deadlines depend on when each reduce landed, which the actions
 * don't record.
 */
export async function vaultView(vault: Vault): Promise<VaultMirror> {
  const reduced = await actions(vault.address, vault.actionState.get());
  const mirror = new VaultMirror(vault.challengeWindow.get().toBigInt());
  reduced.forEach((a) => mirror.dispatched(a));
  mirror.nextReduce(0n, reduced.length);
  if (!mirror.tree.root.equals(vault.noteRoot.get()).toBoolean()) throw Error('rebuilt note root is not the vault root');
  if (!mirror.nullifiers.root.equals(vault.nullifierRoot.get()).toBoolean()) {
    throw Error('rebuilt nullifier root is not the vault root');
  }
  return mirror;
}

/**
 * The pending escapes of `vault`, rebuilt by replaying its `escape` events in order, and checked against
 * its on-chain root. `records` holds every escape still pending, by its current nullifier. The archive
 * lists events oldest block first.
 *
 * o1js's LocalBlockchain lists them newest first and reverses its stored list in place on every read, so
 * a later block could land in the middle of it. On the local chain (`localChain`), every read here is
 * followed by a second one, which leaves the stored list oldest first between reads.
 */
export async function pendingEscapesView(vault: Vault, o: { localChain: boolean }) {
  return (await escapeEvents(vault, o)).view;
}

/**
 * The vault's `escape` events, oldest first, each as its block height and its fields (decimal strings),
 * and the pending escapes they rebuild. Throws unless they rebuild the vault's on-chain root.
 */
export async function escapeEvents(vault: Vault, o: { localChain: boolean }) {
  let blocks = [...(await Mina.fetchEvents(vault.address, TokenId.default))];
  if (o.localChain) {
    await Mina.fetchEvents(vault.address, TokenId.default);
    blocks = blocks.reverse();
  }
  // An account update lists its events newest first (o1js pushes each onto the front), so a reduce's
  // events are reversed back into the order the reduce emitted them; as listed is the fallback.
  const flat = (newestFirst: boolean) =>
    blocks.flatMap((b) => {
      const events = b.events.map((e) => ({ height: BigInt(b.blockHeight.toString()), data: e.data as string[] }));
      return newestFirst ? events.reverse() : events;
    });
  const root = vault.pendingEscapesRoot.get();
  for (const events of [flat(true), flat(false)]) {
    const view = replay(events.map((e) => e.data));
    if (view.escapes.root.equals(root).toBoolean()) return { events, view };
  }
  throw Error("the rebuilt pending escapes are not the vault's");
}

function replay(events: string[][]) {
  const escapes = new PendingEscapes();
  const records = new Map<bigint, PendingEscape>();
  for (const data of events) {
    const { pending, record } = EscapeUpdate.fromFields(data.map((f) => Field(f)));
    const pendingNow = pending.toBoolean();
    escapes.set(record.nullifier, pendingNow ? record.hash() : Field(0));
    if (pendingNow) records.set(record.nullifier.toBigInt(), record);
    else records.delete(record.nullifier.toBigInt());
  }
  return { escapes, records };
}

/**
 * A mirror of `vault` rebuilt wholly from the chain, ready for its next reduce (`nextReduce`), and how many
 * actions wait for one. Its pending escapes are the chain's, but it doesn't list their records.
 */
export async function reduceMirror(vault: Vault) {
  const mirror = await vaultView(vault);
  mirror.escapes = (await pendingEscapesView(vault, { localChain: false })).escapes;
  const reduced = (await actions(vault.address, vault.actionState.get())).length;
  const all = await actions(vault.address);
  all.slice(reduced).forEach((a) => mirror.dispatched(a));
  return { mirror, pending: all.length - reduced };
}

/**
 * The action-stack program's domain. o1js starts its chain of chunk proofs from a dummy proof at 2^14, and
 * `proveChunk` can't prove from a dummy of the wrong domain: `Checked.inv` fails in Pickles's `scalars_env`.
 * A batch with no recursion isn't verified, so a dummy of the right domain does there too.
 */
const ACTION_STACK_DOMAIN_LOG2 = 15;

/**
 * `batchReducer.prepareBatches`, but provable on a chain that checks proofs, for any number of pending
 * action lists. `prepareBatches` leaves the first `maxUpdatesFinalProof` lists to the reduce and proves the
 * rest from a dummy of the wrong domain, so it throws past that. Here the batches come from a reducer that
 * leaves every list to the reduce (so none recurses), and the lists past the limit are proved from a
 * dummy of the action-stack program's domain.
 */
export async function provableBatches() {
  const { initialActionState: empty } = Experimental.BatchReducer;
  const unlimited = new Experimental.BatchReducer({
    actionType: VaultAction,
    batchSize: REDUCE_BATCH_SIZE,
    maxUpdatesFinalProof: Number.MAX_SAFE_INTEGER,
  });
  // The instance `batchReducer.setContractInstance` was given; `contract()` only answers inside a method.
  const contract = batchReducer._contract;
  if (!contract) throw new Error('provableBatches: call batchReducer.setContractInstance(vault) first');
  unlimited.setContractInstance(contract);
  const batches = await unlimited.prepareBatches();
  if (batches.length === 0) return [];

  const dummy = await VaultBatchProof.dummy(Field(0), { actions: empty, stack: empty }, 1, ACTION_STACK_DOMAIN_LOG2);
  const lists = batches[0].batch.witnesses.get();
  const { maxUpdatesFinalProof } = batchReducer;
  if (lists.length <= maxUpdatesFinalProof) return batches.map(({ batch }) => ({ batch, proof: dummy }));
  // Proofs off, o1js's own dummy carries the stack the reduce reads, and is never checked.
  if (!Mina.getProofsEnabled()) return batchReducer.prepareBatches();

  const { maxUpdatesPerProof } = batchReducer.program;
  const endActionState = batches[0].batch.onchainActionState;
  const remaining = lists.slice(maxUpdatesFinalProof);
  const chunks: Unconstrained<typeof lists>[] = [];
  for (let k = 0; k < remaining.length; k += maxUpdatesPerProof) {
    const chunk: typeof lists = [];
    for (let j = 0; j < maxUpdatesPerProof; j++) chunk[j] = remaining[k + j];
    chunks.push(Unconstrained.from(chunk));
  }
  let proof = dummy;
  for (let i = chunks.length - 1; i >= 0; i--) {
    ({ proof } = await batchReducer.program.proveChunk(endActionState, proof, Bool(i < chunks.length - 1), chunks[i]));
  }
  // o1js's own check: a chain that doesn't reach the lists left out fails here.
  proof.publicOutput.actions.assertEquals(Field(remaining[0]!.stateBefore), 'Action stack mismatch');
  const witnesses = Unconstrained.from(lists.slice(0, maxUpdatesFinalProof));
  return batches.map(({ batch }) => ({ batch: { ...batch, isRecursive: Bool(true), witnesses }, proof }));
}

/** Reduces the vaults it tracks, keeping each one's full mirror, pending escapes included. */
export class VaultKeeper {
  private vaults = new Map<string, { mirror: VaultMirror; fed: number }>();

  track(vault: PublicKey) {
    this.vaults.set(vault.toBase58(), { mirror: new VaultMirror(), fed: 0 });
  }

  /**
   * Reduces every pending action of `vault`, one transaction per batch, sent from `from`.
   * `beforeBatch` runs before each batch's transaction, with its index.
   */
  async reduce(vault: Vault, from: Account, beforeBatch?: (index: number) => void) {
    const kept = this.vaults.get(vault.address.toBase58());
    if (!kept) throw Error('not a vault this keeper deployed');
    const all = await actions(vault.address);
    all.slice(kept.fed).forEach((a) => kept.mirror.dispatched(a));
    kept.fed = all.length;

    batchReducer.setContractInstance(vault);
    let index = 0;
    for (const { batch, proof } of await provableBatches()) {
      beforeBatch?.(index++);
      const now = chainSlot();
      const { witnesses, nullifiers, escapes } = kept.mirror.nextReduce(now);
      const tx = await Mina.transaction(from, async () => {
        await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(now));
      });
      await tx.prove();
      await tx.sign([from.key]).send();
    }
  }
}

/** The chain's current slot. */
export function chainSlot(): bigint {
  return Mina.getNetworkState().globalSlotSinceGenesis.toBigint();
}
