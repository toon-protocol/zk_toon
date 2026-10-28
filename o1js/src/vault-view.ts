// The vault's off-chain state as the transaction builder needs it, read from the chain: the note tree and
// the nullifier set, rebuilt by replaying the actions the vault has reduced. Also the local chain's keeper,
// which reduces a vault's pending actions as a keeper would.
import { Field, Mina, PublicKey, UInt64, Unconstrained } from 'o1js';
import { Vault, VaultAction, batchReducer } from './vault.js';
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
      const now = chainNow();
      const { witnesses, nullifiers, escapes } = kept.mirror.nextReduce(now);
      const tx = await Mina.transaction(from, async () => {
        await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(now));
      });
      await tx.prove();
      await tx.sign([from.key]).send();
    }
  }
}

/** The network's timestamp: that of the current slot's start. */
export function chainNow(): bigint {
  const { genesisTimestamp, slotTime } = Mina.getNetworkConstants();
  return genesisTimestamp.toBigInt() + Mina.getNetworkState().globalSlotSinceGenesis.toBigint() * slotTime.toBigInt();
}
