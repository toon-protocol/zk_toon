// The vault's off-chain state as the transaction builder needs it, read from the chain: the note tree and
// the nullifier set, rebuilt by replaying the actions the vault has reduced, and the pending escapes,
// rebuilt by replaying its `escape` events. Also the local chain's keeper,
// which reduces a vault's pending actions as a keeper would.
import { Field, Mina, PublicKey, TokenId, UInt64, Unconstrained } from 'o1js';
import { EscapeUpdate, PendingEscape, PendingEscapes, Vault, VaultAction, batchReducer } from './vault.js';
import { VaultMirror } from './vault-mirror.js';

type Account = Awaited<ReturnType<typeof Mina.LocalBlockchain>>['testAccounts'][number];

/** Every action `vault` has dispatched, oldest first, up to `endActionState` when given. */
async function actions(vault: PublicKey, endActionState?: Field): Promise<VaultAction[]> {
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
  const mirror = new VaultMirror();
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

/** Reduces the vaults it tracks, keeping each one's full mirror, pending escapes included. */
export class VaultKeeper {
  private vaults = new Map<string, { mirror: VaultMirror; fed: number }>();

  track(vault: PublicKey) {
    this.vaults.set(vault.toBase58(), { mirror: new VaultMirror(), fed: 0 });
  }

  /** Reduces every pending action of `vault`, one transaction per batch, sent from `from`. */
  async reduce(vault: Vault, from: Account) {
    const kept = this.vaults.get(vault.address.toBase58());
    if (!kept) throw Error('not a vault this keeper deployed');
    const all = await actions(vault.address);
    all.slice(kept.fed).forEach((a) => kept.mirror.dispatched(a));
    kept.fed = all.length;

    batchReducer.setContractInstance(vault);
    for (const { batch, proof } of await batchReducer.prepareBatches()) {
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
