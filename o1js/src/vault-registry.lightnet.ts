// The vault registry on a node (#81): a real-length zkApp URI, and the rogue key pair, a key whose data is the
// attacker's own under the published vault code hash. LocalBlockchain accepts that pair on a new account (ADR 0011).
// So does the lightnet's daemon, and the account is not stuck: see lightnet/README.md. The vault check refuses it by
// the key's data, which is why the check compares the data and not only the hash.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  AccountUpdate, Mina, PrivateKey, PublicKey, Signature, SmartContract, Types, UInt64, VerificationKey, declareMethods, fetchAccount,
} from 'o1js';
import { type Keys, buildKeys } from './keys.js';
import { MINA, connectLightnet, lightnetLanding } from './lightnet.js';
import { Vault, setupFields } from './vault.js';
import { chainReader, checkVault } from './vault-check.js';
import { Uri, type Registry, registryDeployTx, vaultKey } from './vault-registry.js';

const FEE = 100_000_000;
const { sender, release } = await connectLightnet();
const { clockSlot, submit, land, landAt } = lightnetLanding(MINA, sender);

/** A URI as long as an operator's fork-notice location might be: a host, a path and the vault's address. */
const realUri = (vault: PublicKey) => `https://fork-notices.operator.example/toon/zk-vaults/mina-devnet/${vault.toBase58()}/notice.json`;

let registry: Registry;
let keys: Keys;
let published: VerificationKey;
/** The register transaction for a fresh vault, proved for `slot`. */
async function registration(vault: PrivateKey, slot: bigint, o: { uri?: string; vk?: VerificationKey } = {}) {
  await fetchAccount({ publicKey: registry.address });
  const uri = Uri.from(o.uri ?? realUri(vault.toPublicKey()));
  const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
    AccountUpdate.fundNewAccount(sender);
    await registry.register(vault.toPublicKey(), o.vk ?? published, UInt64.from(slot), uri);
  });
  await tx.prove();
  return tx;
}
/** The key the node stores for `address`, data and hash, read straight from its GraphQL. */
async function storedKey(address: PublicKey) {
  const response = await fetch(MINA, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: `{ account(publicKey: "${address.toBase58()}") { verificationKey { verificationKey hash } } }` }),
  });
  const { data } = await response.json();
  return data.account?.verificationKey as { verificationKey: string; hash: string } | null | undefined;
}
const account = async (address: PublicKey) => {
  const { account } = await fetchAccount({ publicKey: address });
  return account ? Types.Account.toJSON(account) : undefined;
};

describe('the vault registry on a proofs-on lightnet', () => {
  beforeAll(async () => {
    expect(Mina.getProofsEnabled()).toBe(true);
    keys = await buildKeys();
    published = await vaultKey();
    const key = PrivateKey.random();
    let deployed: Awaited<ReturnType<typeof registryDeployTx>> | undefined;
    await land('registry deploy', async () => {
      deployed = await registryDeployTx({ sender, fee: FEE }, key);
      await deployed.tx.prove();
      return deployed.tx;
    }, [key]);
    registry = deployed!.registry;
  });
  afterAll(release);

  it('the rogue key pair, on a chain where no account has had the published key', async () => {
    class Rogue extends SmartContract {
      async poke() {}
    }
    declareMethods(Rogue, { poke: [] });
    const rogueKey = (await Rogue.compile()).verificationKey;
    const rogue = new VerificationKey({ data: rogueKey.data, hash: published.hash });
    const key = PrivateKey.random();
    const vault = key.toPublicKey();
    console.log(`rogue vault: ${vault.toBase58()}`);
    // Built again only when it misses its slot: any other answer is the outcome.
    let outcome = 'not sent';
    for (let attempt = 1; attempt <= 6; attempt++) {
      const slot = (await clockSlot()) + 6n;
      const tx = await registration(key, slot, { vk: rogue });
      if ((await clockSlot()) >= slot) continue;
      while ((await clockSlot()) < slot - 1n) await new Promise((r) => setTimeout(r, 1_000));
      const sent = await tx.sign([sender.key, key]).safeSend();
      if (sent.status === 'rejected') {
        outcome = `refused at send: ${JSON.stringify(sent.errors)}`;
        break;
      }
      const done = await sent.safeWait({ maxAttempts: 60, interval: 5_000 });
      outcome = done.status === 'rejected' ? `failed in a block: ${JSON.stringify(done.errors)}` : `applied: ${sent.hash}`;
      if (!outcome.includes('Valid_while_precondition_unsatisfied')) break;
    }
    console.log('rogue registration:', outcome);
    expect(outcome).toMatch(/^applied/);
    const stored = await storedKey(vault);
    console.log('rogue stored key:', stored ? JSON.stringify({
      hash: stored.hash, isRogueData: stored.verificationKey === rogue.data, isPublishedData: stored.verificationKey === published.data,
    }) : 'no account');
    expect(stored?.hash).toBe(published.hash.toString());
    expect(stored?.verificationKey).toBe(rogue.data);
    // Refused by its key's data, whatever else the archive has caught up with.
    const verdict = await checkVault(vault, {
      key: keys.vault.verificationKey, registryKey: keys.registry.verificationKey, registry: registry.address,
      reader: chainReader({ localChain: false }),
    });
    console.log('rogue vault check:', JSON.stringify(verdict));
    expect(verdict.pass ? [] : verdict.refusals.map((r) => r.check)).toContain('keyData');
    const stateKey = PrivateKey.random().toPublicKey();
    const signature = Signature.create(key, setupFields(vault, stateKey, sender));
    const setup = await Mina.transaction({ sender, fee: FEE }, async () => { await new Vault(vault).setup(stateKey, sender, signature); });
    await setup.prove();
    const setupRefused = await submit(setup, []);
    console.log('rogue setup (published proof):', setupRefused ?? 'applied');
    const poke = await Mina.transaction({ sender, fee: FEE }, async () => { await new Rogue(vault).poke(); });
    await poke.prove();
    const pokeRefused = await submit(poke, []);
    console.log('rogue poke (rogue proof):', pokeRefused ?? 'applied');
    // Not stuck: one of the two contracts controls the account. On a fresh chain it was the rogue one; after an honest
    // vault had registered, the published one (lightnet/README.md). Which, depends on the node, not on the chain's rules.
    expect([setupRefused === undefined, pokeRefused === undefined].filter(Boolean)).toHaveLength(1);
    expect(setupRefused ?? pokeRefused).toContain('Invalid_proof');
  });

  it('registers a vault with a real-length URI', async () => {
    const key = PrivateKey.random();
    const uri = realUri(key.toPublicKey());
    console.log(`URI of ${uri.length} characters`);
    await landAt('register', (slot) => registration(key, slot, { uri }), 4n, [key]);
    const vault = await account(key.toPublicKey());
    expect(vault?.zkapp?.zkappUri).toBe(uri);
    expect(vault?.zkapp?.verificationKey?.hash).toBe(published.hash.toString());
  });

});
