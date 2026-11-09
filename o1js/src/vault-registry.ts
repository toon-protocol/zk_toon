// The vault registry (ADR 0011): a zkApp that deploys each vault in one transaction and lists it. A vault deployed
// under its own key can have anything written to it before the account is locked (ADR 0008, "What a pass doesn't
// show"). A vault the registry deployed never had an unlocked phase: `register`'s proof requires that the account is
// new, that its key is the vault code hash, that its permissions are ADR 0006's table, that its state is what `init`
// writes and that its zkApp URI is the one given. Then it records the address as an action. The vault check refuses a
// vault the pinned registry doesn't list.
//
// The registry fixes the vault code hash in its circuit, and the published hash is a build output, so the registry is
// a class built by a factory, after the vault compiles.
import {
  AccountUpdate, Bool, Cache, Field, Mina, PrivateKey, PublicKey, Reducer, SmartContract, Struct, UInt64, VerificationKey,
  declareMethods,
} from 'o1js';
import { VAULT_URI, Vault, VaultState, lockedPermissions } from './vault.js';

/** A zkApp URI with its hash, as an account update carries it. `data` is the operator's choice; any URI is accepted. */
export class Uri extends Struct({ data: String, hash: Field }) {
  /** The URI and the hash o1js writes for it. */
  static from(data: string): Uri {
    // The hash is the transaction's own, read off an update that sets it: no deep import of o1js's bindings. The update
    // is `default`, not `create`, so it isn't attached to a transaction the caller has open.
    const update = AccountUpdate.default(PrivateKey.random().toPublicKey());
    update.account.zkappUri.set(data);
    return new Uri({ data, hash: update.body.update.zkappUri.value.hash });
  }
}

/** The registry's account permissions: ADR 0006's table. It has no fork notice, as it is replaced at a fork, not upgraded. */
export const registryPermissions = lockedPermissions;

/** The registry for vaults of verification key hash `codeHash`. */
export function vaultRegistry(codeHash: Field) {
  class VaultRegistry extends SmartContract {
    /** The vaults registered, each by its address. */
    reducer = Reducer({ actionType: PublicKey });

    /**
     * Deploys the vault at `vault` in this transaction, which the vault's key signs. `slot` is the slot to aim at:
     * the creation slot, and the first of the two slots the transaction can land in. The transaction must also
     * pay the account creation fee (`AccountUpdate.fundNewAccount`).
     */
    async register(vault: PublicKey, vk: VerificationKey, slot: UInt64, uri: Uri) {
      vk.hash.assertEquals(codeHash, 'not the published vault');
      this.currentSlot.requireBetween(slot.toUInt32(), slot.add(1).toUInt32());
      const update = AccountUpdate.createSigned(vault);
      update.account.isNew.requireEquals(Bool(true));
      update.body.update.verificationKey = { isSome: Bool(true), value: { data: vk.data, hash: vk.hash } };
      update.account.permissions.set(lockedPermissions());
      update.body.update.zkappUri = { isSome: Bool(true), value: { data: uri.data, hash: uri.hash } } as any;
      const fields = VaultState.toFields(VaultState.initial(slot));
      update.body.update.appState.forEach((_, i) => {
        update.body.update.appState[i] = { isSome: Bool(true), value: fields[i] ?? Field(0) };
      });
      this.reducer.dispatch(vault);
    }
  }
  declareMethods(VaultRegistry, { register: [PublicKey, VerificationKey, UInt64, Uri] } as Record<string, any[]>);
  return VaultRegistry;
}

export type Registry = InstanceType<ReturnType<typeof vaultRegistry>>;
type Local = Awaited<ReturnType<typeof Mina.LocalBlockchain>>;
type Account = Local['testAccounts'][number];

/** The key the vault carries: the compiled one, else o1js's dummy while proofs are off, else compiled now. */
export async function vaultKey(): Promise<VerificationKey> {
  const compiled = Vault._verificationKey;
  if (compiled) return new VerificationKey(compiled);
  if (Mina.getProofsEnabled()) return new VerificationKey((await Vault.compile()).verificationKey);
  return VerificationKey.dummy();
}

const classes = new Map<string, { cls: ReturnType<typeof vaultRegistry>; compiled: boolean }>();
/**
 * The registry class for `codeHash`, built once, and compiled once: when proofs are on, or when asked (`compile`),
 * so that a registry deployed from it carries the compiled key.
 */
export async function registryClass(codeHash: Field, o: { cache?: Cache; compile?: boolean } = {}) {
  const key = codeHash.toString();
  let entry = classes.get(key);
  if (!entry) classes.set(key, (entry = { cls: vaultRegistry(codeHash), compiled: false }));
  if (!entry.compiled && (o.compile ?? Mina.getProofsEnabled())) {
    entry.compiled = true;
    await entry.cls.compile(o.cache ? { cache: o.cache } : undefined);
  }
  return entry.cls;
}

/**
 * The transaction that deploys a registry at `key`'s address for the vault this build compiles, locked under ADR 0006's
 * permissions in the update that creates the account (`isNew`), so the command itself shows the registry never had an
 * unlocked phase. `payer` pays and signs with `key`.
 */
export async function registryDeployTx(payer: PublicKey | { sender: PublicKey; fee?: number | string | UInt64 }, key: PrivateKey) {
  const cls = await registryClass((await vaultKey()).hash);
  const registry = new cls(key.toPublicKey());
  const sender = payer instanceof PublicKey ? payer : payer.sender;
  const tx = await Mina.transaction(payer, async () => {
    AccountUpdate.fundNewAccount(sender);
    await registry.deploy();
    registry.account.isNew.requireEquals(Bool(true));
    registry.account.permissions.set(registryPermissions());
  });
  return { tx, registry };
}

/** Deploys a registry for the vault this build compiles, under ADR 0006's permissions. */
export async function deployRegistry(deployer: Account, o: { key?: PrivateKey } = {}) {
  const key = o.key ?? PrivateKey.random();
  const { tx, registry } = await registryDeployTx(deployer, key);
  await tx.prove();
  await tx.sign([deployer.key, key]).send();
  return registry;
}

/**
 * The transaction that registers and deploys the vault at `vaultKey`'s address from `payer`, which also pays the
 * account creation fee. `slot` is the slot to aim at; omitted, the network's current one.
 */
export async function registerTx(registry: Registry, payer: Account, o: {
  vaultKey: PrivateKey; slot?: bigint; uri?: string; vk?: VerificationKey;
}) {
  const slot = o.slot ?? Mina.getNetworkState().globalSlotSinceGenesis.toBigint();
  const [vk, uri] = [o.vk ?? (await vaultKey()), Uri.from(o.uri ?? VAULT_URI)];
  return Mina.transaction(payer, async () => {
    AccountUpdate.fundNewAccount(payer);
    await registry.register(o.vaultKey.toPublicKey(), vk, UInt64.from(slot), uri);
  });
}

/** Registers, proves and sends the vault at `vaultKey`'s address, signed by it and by `payer`. */
export async function registerVault(registry: Registry, payer: Account, o: Parameters<typeof registerTx>[2]) {
  const tx = await registerTx(registry, payer, o);
  await tx.prove();
  await (await tx.sign([payer.key, o.vaultKey]).send()).wait();
  return new Vault(o.vaultKey.toPublicKey());
}
