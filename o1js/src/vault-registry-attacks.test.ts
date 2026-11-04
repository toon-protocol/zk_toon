// The vault registry (ADR 0011) on a chain that checks proofs: the honest registration, and each attack on it, with the
// reason the chain gives for refusing it. Each is in the proofs-on set (`proofs-on.ts`).
import { beforeAll, describe, expect, it } from 'vitest';
import {
  AccountUpdate, Bool, Field, Mina, Permissions, PrivateKey, PublicKey, Signature, SmartContract, Types, UInt64, VerificationKey, declareMethods,
} from 'o1js';
import { buildKeys } from './keys.js';
import { PROOFS_ON } from './proofs-on.js';
import { Vault, VaultState, setupFields } from './vault.js';
import { Uri, type Registry, deployRegistry, registerTx, registryClass, vaultKey } from './vault-registry.js';
import { now } from './vault-harness.js';

const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);
const [payer, deployer] = Local.testAccounts;

let registry: Registry;
let published: VerificationKey;
const REGISTRY_KEY = PrivateKey.random();
type Tx = Awaited<ReturnType<typeof Mina.transaction>>;
/** What the chain says of the registry's update when its proof no longer verifies: it can't write its action without one. */
const AUTHORIZATION_FAILED = /Cannot update field 'actions' because permission for this field is 'Proof', but the required authorization was not provided or is invalid/;
const vaultUpdate = (tx: Tx, vault: PublicKey) => tx.transaction.accountUpdates.find((a) => a.body.publicKey.equals(vault).toBoolean())!;
beforeAll(async () => {
  // Compiles the circuits, then the vault, then the registry built for its code hash.
  await buildKeys();
  published = await vaultKey();
  registry = await deployRegistry(payer, { key: REGISTRY_KEY });
}, 3_600_000);

const T = 1_800_000;
const json = (address: PublicKey) => Types.Account.toJSON(Mina.getAccount(address));

/** Proves `build`'s transaction, signs it as `signers` and sends it. */
async function send(tx: Awaited<ReturnType<typeof Mina.transaction>>, ...signers: PrivateKey[]) {
  await tx.prove();
  return (await tx.sign([deployer.key, ...signers]).send()).wait();
}
/** The reason the chain refuses, which is the first thing in the error. */
async function reason(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (e) {
    return String((e as Error).message);
  }
  throw Error('the transaction was accepted');
}
/** A registration of a fresh vault with `extra` run inside the transaction, before or after `register`. */
async function around(o: { before?: (vault: PublicKey) => void; after?: (vault: PublicKey) => void; vk?: VerificationKey; key?: PrivateKey } = {}) {
  const key = o.key ?? PrivateKey.random();
  const vault = key.toPublicKey();
  const [vk, uri] = [o.vk ?? published, Uri.from('https://example.org/toon-vault')];
  const tx = await Mina.transaction(deployer, async () => {
    AccountUpdate.fundNewAccount(deployer);
    o.before?.(vault);
    await registry.register(vault, vk, UInt64.from(now()), uri);
    o.after?.(vault);
  });
  return { tx, key, vault };
}
/** A signed write to `vault` that leaves its nonce alone, so that only the field written can be refused (the nonce is `Impossible` to change). */
const writes = (vault: PublicKey, body: (u: AccountUpdate) => void) => {
  const u = AccountUpdate.createSigned(vault);
  u.body.incrementNonce = Bool(false);
  u.body.useFullCommitment = Bool(true);
  body(u);
};

describe('a registry on a chain that checks proofs', () => {
  it(PROOFS_ON.registry, async () => {
    const key = PrivateKey.random();
    const tx = await registerTx(registry, deployer, { vaultKey: key });
    await send(tx, key);
    const account = json(key.toPublicKey());
    expect(account.zkapp!.verificationKey!.hash).toBe(published.hash.toString());
    const fields = VaultState.toFields(VaultState.initial(new Vault(key.toPublicKey()).creationTime.get())).map(String);
    expect(account.zkapp!.appState).toEqual([...fields, ...Array(account.zkapp!.appState.length - fields.length).fill('0')]);
    const lists = await Mina.fetchActions(registry.address);
    if ('error' in lists) throw Error(JSON.stringify(lists.error));
    expect(lists.flatMap((l) => l.actions).map((a) => PublicKey.fromFields(a.map((f) => Field(f))).toBase58())).toContain(key.toPublicKey().toBase58());
  }, T);

  it(PROOFS_ON.registryExisting, async () => {
    const key = PrivateKey.random();
    await send(await Mina.transaction(deployer, async () => {
      AccountUpdate.fundNewAccount(deployer);
      AccountUpdate.createSigned(deployer).send({ to: key.toPublicKey(), amount: UInt64.from(1) });
    }));
    const tx = await registerTx(registry, deployer, { vaultKey: key });
    expect(await reason(send(tx, key))).toContain('Account_is_new_precondition_unsatisfied');
  }, T);

  it(PROOFS_ON.registryEarlier, async () => {
    const { tx, key } = await around({ before: (v) => writes(v, (u) => { u.body.update.appState[0] = { isSome: Bool(true), value: Field(7) }; }) });
    expect(await reason(send(tx, key))).toContain('Account_is_new_precondition_unsatisfied');
  }, T);

  it(PROOFS_ON.registryLater, async () => {
    const later: [string, (u: AccountUpdate) => void][] = [
      ['Update_not_permitted_app_state', (u) => { u.body.update.appState[0] = { isSome: Bool(true), value: Field(7) }; }],
      ['Update_not_permitted_action_state', (u) => { u.body.actions = AccountUpdate.Actions.pushEvent(u.body.actions, [Field(1)]); }],
      ['Update_not_permitted_permissions', (u) => { u.account.permissions.set(Permissions.default()); }],
    ];
    for (const [expected, body] of later) {
      const { tx, key } = await around({ after: (v) => writes(v, body) });
      expect(await reason(send(tx, key))).toContain(expected);
    }
    // A later write the permissions allow is accepted, so the refusals above come from the permissions.
    const { tx, key } = await around({ after: (v) => writes(v, (u) => u.account.delegate.set(deployer)) });
    await send(tx, key);
  }, T);

  it(PROOFS_ON.registryTampered, async () => {
    const tampers: [string, (tx: Tx, vault: PublicKey) => void][] = [
      ['the vault state', (tx, v) => { vaultUpdate(tx, v).body.update.appState[0] = { isSome: Bool(true), value: Field(9) }; }],
      ['the creation slot', (tx, v) => { vaultUpdate(tx, v).body.update.appState[5] = { isSome: Bool(true), value: Field(1) }; }],
      ['the permissions', (tx, v) => { vaultUpdate(tx, v).body.update.permissions.value.editState = Permissions.signature(); }],
      ['the actions', (tx, v) => { const u = vaultUpdate(tx, v); u.body.actions = AccountUpdate.Actions.pushEvent(u.body.actions, [Field(1)]); }],
      ["the registry's slot window", (tx) => {
        const u = tx.transaction.accountUpdates.find((a) => a.body.publicKey.equals(registry.address).toBoolean())!;
        u.body.preconditions.validWhile.value.upper = u.body.preconditions.validWhile.value.upper.add(100);
      }],
    ];
    for (const [what, tamper] of tampers) {
      const { tx, key, vault } = await around();
      await tx.prove();
      tamper(tx, vault);
      const message = await reason(tx.sign([deployer.key, key]).send());
      expect(message, what).toMatch(AUTHORIZATION_FAILED);
    }
    // Untampered, the same transaction is accepted.
    const { tx, key } = await around();
    await send(tx, key);
  }, T);

  it(PROOFS_ON.registryOtherKey, async () => {
    const rogue = (await registryClass(published.hash))._verificationKey!;
    await expect(around({ vk: new VerificationKey(rogue) })).rejects.toThrow('not the published vault');
    await expect(around({ vk: await VerificationKey.dummy() })).rejects.toThrow('not the published vault');
  }, T);

  it(PROOFS_ON.registryNoProof, async () => {
    const tx = await Mina.transaction(deployer, async () => {
      const u = AccountUpdate.createSigned(registry.address);
      u.body.incrementNonce = Bool(false);
      u.body.useFullCommitment = Bool(true);
      u.body.actions = AccountUpdate.Actions.pushEvent(u.body.actions, PublicKey.toFields(PrivateKey.random().toPublicKey()));
    });
    expect(await reason(send(tx, REGISTRY_KEY))).toContain("Cannot update field 'actions' because permission for this field is 'Proof'");
  }, T);

  it(PROOFS_ON.registryRogueKey, async () => {
    // A key of the attacker's own, under the published hash. A new account is the one place LocalBlockchain doesn't
    // check that a key's data hashes to its hash, so the registration is accepted.
    class Rogue extends SmartContract {
      async poke() {}
    }
    declareMethods(Rogue, { poke: [] });
    const rogueKey = (await Rogue.compile()).verificationKey;
    const rogue = new VerificationKey({ data: rogueKey.data, hash: published.hash });
    expect(rogue.data).not.toBe(published.data);
    const key = PrivateKey.random();
    const { tx } = await around({ vk: rogue, key });
    await send(tx, key);
    const address = key.toPublicKey();
    expect(json(address).zkapp!.verificationKey!.hash).toBe(published.hash.toString());

    // Stuck: the published contract's proof is refused ...
    const vault = new Vault(address);
    const stateKey = PrivateKey.random().toPublicKey();
    const signature = Signature.create(key, setupFields(address, stateKey, deployer));
    const setup = await Mina.transaction(deployer, async () => { await vault.setup(stateKey, deployer, signature); });
    expect(await reason(send(setup))).toContain("Cannot update field 'appState' because permission for this field is 'Proof'");
    // ... and so is a proof of the rogue contract the data belongs to.
    const poke = await Mina.transaction(deployer, async () => { await new Rogue(address).poke(); });
    expect(await reason(send(poke))).toContain('One or more proofs were invalid');
    expect(Mina.getAccount(address).zkapp!.appState[0]!.toString()).not.toBe(stateKey.x.toString());
  }, T);

  it(PROOFS_ON.registryUris, async () => {
    const uris = ['https://operator-a.example/notices', 'https://operator-b.example/other/place'];
    const vaults = [];
    for (const uri of uris) {
      const key = PrivateKey.random();
      await send(await registerTx(registry, deployer, { vaultKey: key, uri }), key);
      vaults.push(key.toPublicKey());
    }
    // One compiled key, two URIs, each as given.
    expect(vaults.map((v) => json(v).zkapp!.zkappUri)).toEqual(uris);
    expect(json(vaults[0]!).zkapp!.verificationKey).toEqual(json(vaults[1]!).zkapp!.verificationKey);
    expect(uris[0]).not.toBe(uris[1]);

    // The URI is bound by the proof: changed after proving, with its hash, the transaction is refused.
    const key = PrivateKey.random();
    const tx = await registerTx(registry, deployer, { vaultKey: key, uri: uris[0] });
    await tx.prove();
    const swapped = Uri.from('https://evil.example/notices');
    vaultUpdate(tx, key.toPublicKey()).body.update.zkappUri = { isSome: Bool(true), value: { data: swapped.data, hash: swapped.hash } } as never;
    const message = await reason(tx.sign([deployer.key, key]).send());
    expect(message).toMatch(AUTHORIZATION_FAILED);
  }, T);
});
