// The vault registry (ADR 0011) with proofs off: what `register` writes, against what a direct deploy writes. The
// attacks on it, which need a chain that checks proofs, are in vault-registry-attacks.test.ts.
import { describe, expect, it } from 'vitest';
import { AccountUpdate, Field, Mina, PrivateKey, PublicKey, Types, UInt64 } from 'o1js';
import { VAULT_URI, Vault, lockedPermissions } from './vault.js';
import { Uri, deployRegistry, registerVault } from './vault-registry.js';
import { now } from './vault-harness.js';

const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
const [payer, deployer] = Local.testAccounts;

/** A vault deployed directly under its own key, as a deployer can. */
async function direct(slot?: bigint) {
  const key = PrivateKey.random();
  const vault = new Vault(key.toPublicKey());
  const tx = await Mina.transaction(deployer, async () => {
    AccountUpdate.fundNewAccount(deployer);
    await vault.deploy({ zkappUri: VAULT_URI, slot: slot === undefined ? undefined : UInt64.from(slot) });
  });
  await tx.prove();
  await tx.sign([deployer.key, key]).send();
  return vault;
}
const json = (address: PublicKey) => Types.Account.toJSON(Mina.getAccount(address));

describe('a vault the registry deploys', { timeout: 120_000 }, () => {
  it("is what a direct deploy writes: the same state field by field, the same permissions, key, URI and delegate", async () => {
    const registry = await deployRegistry(payer);
    Local.incrementGlobalSlot(5);
    const registered = await registerVault(registry, deployer, { vaultKey: PrivateKey.random(), slot: now() });
    const deployed = await direct(now());
    const [a, b] = [json(registered.address), json(deployed.address)];

    expect(a.zkapp!.appState).toHaveLength(b.zkapp!.appState.length);
    a.zkapp!.appState.forEach((field, i) => expect(field, `state field ${i}`).toBe(b.zkapp!.appState[i]));
    for (const name of Object.keys(lockedPermissions())) {
      expect(a.permissions[name as keyof typeof a.permissions], `permission ${name}`).toEqual(b.permissions[name as keyof typeof b.permissions]);
    }
    expect(a.permissions).toEqual(b.permissions);
    expect(a.zkapp!.verificationKey).toEqual(b.zkapp!.verificationKey);
    expect(a.zkapp!.zkappUri).toBe(VAULT_URI);
    expect(a.zkapp!.zkappUri).toBe(b.zkapp!.zkappUri);
    expect(a.zkapp!.provedState).toBe(b.zkapp!.provedState);
    expect(a.zkapp!.actionState).toEqual(b.zkapp!.actionState);
    expect([a.delegate, a.votingFor, a.tokenSymbol, a.timing, a.balance, a.nonce]).toEqual([a.publicKey, '0', '', b.timing, '0', b.nonce]);
    expect(b.delegate).toBe(b.publicKey);
    expect(a.timing.isTimed).toBe(false);
  });

  it('records the registration slot as creationTime, and applies only in the slot or the next', async () => {
    const registry = await deployRegistry(payer);
    Local.incrementGlobalSlot(20);
    const target = now();
    const vault = await registerVault(registry, deployer, { vaultKey: PrivateKey.random(), slot: target });
    expect(vault.creationTime.get().toBigInt()).toBe(target);

    const refused = (slot: bigint) => registerVault(registry, deployer, { vaultKey: PrivateKey.random(), slot });
    await expect(refused(now() + 1n)).rejects.toThrow(/Valid_while_precondition_unsatisfied/);
    await expect(refused(now() - 2n)).rejects.toThrow(/Valid_while_precondition_unsatisfied/);
    expect((await refused(now() - 1n)).creationTime.get().toBigInt()).toBe(now() - 1n);
  });

  it("is listed by the registry as an action holding only its address, and in the order registered", async () => {
    const registry = await deployRegistry(payer);
    const [first, second] = [PrivateKey.random(), PrivateKey.random()];
    await registerVault(registry, deployer, { vaultKey: first });
    await registerVault(registry, deployer, { vaultKey: second });
    const lists = await Mina.fetchActions(registry.address);
    if ('error' in lists) throw Error(JSON.stringify(lists.error));
    const entries = lists.flatMap((l) => l.actions);
    expect(entries.map((e) => PublicKey.fromFields(e.map((f) => Field(f))).toBase58()))
      .toEqual([first.toPublicKey().toBase58(), second.toPublicKey().toBase58()]);
    expect(entries.every((e) => e.length === 2)).toBe(true);
  });

  it('takes any zkApp URI, whatever the operator chose', async () => {
    const registry = await deployRegistry(payer);
    for (const uri of ['https://operator.example/notices', '', 'ipfs://anything at all']) {
      const vault = await registerVault(registry, deployer, { vaultKey: PrivateKey.random(), uri });
      expect(json(vault.address).zkapp!.zkappUri).toBe(uri);
    }
  });

  it('pays the account creation fee from the transaction, as a direct deploy does', async () => {
    const registry = await deployRegistry(payer);
    const before = Mina.getBalance(deployer).toBigInt();
    await registerVault(registry, deployer, { vaultKey: PrivateKey.random() });
    const registered = before - Mina.getBalance(deployer).toBigInt();
    const middle = Mina.getBalance(deployer).toBigInt();
    await direct();
    expect(registered).toBe(middle - Mina.getBalance(deployer).toBigInt());
  });
});

describe('the URI helper', () => {
  it("gives the hash o1js writes for the URI, and adds nothing to a transaction it's called in", async () => {
    const update = AccountUpdate.default(PrivateKey.random().toPublicKey());
    update.account.zkappUri.set(VAULT_URI);
    expect(Uri.from(VAULT_URI).hash).toEqual(update.body.update.zkappUri.value.hash);
    expect(Uri.from('https://other.example').hash).not.toEqual(Uri.from(VAULT_URI).hash);
    const tx = await Mina.transaction(deployer, async () => {
      Uri.from(VAULT_URI);
    });
    expect(tx.transaction.accountUpdates).toHaveLength(0);
  });
});

describe('the registry itself', { timeout: 120_000 }, () => {
  it("is deployed under ADR 0006's permissions, which the vault shares, and holds no state", async () => {
    const registry = await deployRegistry(payer);
    const { permissions, zkapp } = json(registry.address);
    expect(permissions.editActionState).toBe('Proof');
    expect(permissions.setVerificationKey).toEqual({ auth: 'Impossible', txnVersion: expect.any(String) });
    expect(permissions.setPermissions).toBe('Impossible');
    const vault = await registerVault(registry, deployer, { vaultKey: PrivateKey.random() });
    expect(permissions).toEqual(json(vault.address).permissions);
    expect(zkapp!.appState.every((f) => f === '0')).toBe(true);
  });
});
