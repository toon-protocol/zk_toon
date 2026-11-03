// The published verification keys (#16): what each build writes for a reviewer to check a zk edge's
// greeting pins against (toon-protocol/connector#1511).
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { AccountUpdate, Mina, PrivateKey, Signature, VerificationKey, verify } from 'o1js';
import { buildKeys } from './keys.js';
import { PROOFS_ON } from './proofs-on.js';
import { RequestProgram } from './request.js';
import { defaultSample, buildSample } from './request-sample.js';
import { VAULT_URI, Vault, setupFields } from './vault.js';
import { chainReader, checkVault } from './vault-check.js';

const o1jsVersion = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.o1js;

describe('the published keys', () => {
  it(PROOFS_ON.vault, async () => {
    const keys = await buildKeys();
    expect(keys.o1js).toBe(o1jsVersion);
    expect(Object.keys(keys.circuits).sort()).toEqual(['request', 'vaultReducer', 'withdrawal']);
    expect(keys.circuits.request.methods?.sort()).toEqual(['subsidised', 'unsubsidised']);

    // A vault deployed from this build carries the published code hash as its verification key.
    const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
    Mina.setActiveInstance(Local);
    const [payer] = Local.testAccounts;
    const vaultKey = PrivateKey.random();
    const vault = new Vault(vaultKey.toPublicKey());
    const tx = await Mina.transaction(payer, async () => {
      AccountUpdate.fundNewAccount(payer);
      await vault.deploy({ zkappUri: VAULT_URI });
    });
    await tx.prove();
    await tx.sign([payer.key, vaultKey]).send();
    const onChain = Mina.getAccount(vault.address).zkapp!.verificationKey!;
    expect(onChain.hash.toString()).toBe(keys.vault.codeHash);
    expect(onChain.data).toBe(keys.vault.verificationKey.data);

    // The vault check (ADR 0008) passes that vault under the published code hash, and no other.
    const stateKey = PrivateKey.random().toPublicKey();
    const signature = Signature.create(vaultKey, setupFields(vault.address, stateKey, payer));
    const setup = await Mina.transaction(payer, async () => {
      await vault.setup(stateKey, payer, signature);
    });
    await setup.prove();
    await setup.sign([payer.key]).send();
    const reader = chainReader({ localChain: true });
    expect(await checkVault(vault.address, { codeHash: keys.vault.codeHash, reader })).toEqual({ pass: true, dispatched: 0, reduced: 0 });
    expect((await checkVault(vault.address, { codeHash: keys.circuits.request.verificationKey.hash, reader })).pass).toBe(false);

    // A real request proof verifies against the published request key, read back from its JSON.
    const published = new VerificationKey(VerificationKey.fromJSON(keys.circuits.request.verificationKey));
    expect(published.hash.toString()).toBe(keys.circuits.request.verificationKey.hash);
    const s = buildSample(defaultSample());
    const { proof } = await RequestProgram.unsubsidised(s.pub, s.priv);
    expect(await verify(proof, published)).toBe(true);
  }, 1_800_000);
});
