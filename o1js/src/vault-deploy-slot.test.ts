import { describe, expect, it } from 'vitest';
import { AccountUpdate, Mina, PrivateKey } from 'o1js';
import { VAULT_URI, Vault } from './vault.js';

// Proofs off: the contract logic runs, but no circuit is proven.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);

describe('a vault deploy that names a slot', () => {
  const [deployer] = Local.testAccounts;
  const now = () => Mina.getNetworkState().globalSlotSinceGenesis.toBigint();

  /** Deploys a fresh vault, aimed at `slot` if given, and returns it. */
  async function deploy(slot?: bigint) {
    const key = PrivateKey.random();
    const vault = new Vault(key.toPublicKey());
    const tx = await Mina.transaction(deployer, async () => {
      AccountUpdate.fundNewAccount(deployer);
      await vault.deploy({ zkappUri: VAULT_URI, slot });
    });
    await tx.prove();
    await tx.sign([deployer.key, key]).send();
    return vault;
  }

  it('records the named slot as creationTime, and applies when the chain is at it or the next slot', async () => {
    Local.incrementGlobalSlot(20);
    const target = now();
    expect((await deploy(target)).creationTime.get().toBigInt()).toBe(target);

    // One slot later the named slot is one behind the chain: still inside the two-slot range.
    Local.incrementGlobalSlot(20);
    const earlier = now();
    Local.incrementGlobalSlot(1);
    expect((await deploy(earlier)).creationTime.get().toBigInt()).toBe(earlier);
  });

  it('is refused before the named slot and more than one slot after it', async () => {
    Local.incrementGlobalSlot(20);
    const t = now();
    await expect(deploy(t + 1n)).rejects.toThrow(/Valid_while_precondition_unsatisfied/);
    await expect(deploy(t - 2n)).rejects.toThrow(/Valid_while_precondition_unsatisfied/);
    expect((await deploy(t - 1n)).creationTime.get().toBigInt()).toBe(t - 1n);
  });

  it('records the network slot when no slot is named, and a named slot does not leak into the next deploy', async () => {
    Local.incrementGlobalSlot(20);
    const aimed = now() - 1n;
    await deploy(aimed);
    Local.incrementGlobalSlot(10);
    expect((await deploy()).creationTime.get().toBigInt()).toBe(now());
  });
});
