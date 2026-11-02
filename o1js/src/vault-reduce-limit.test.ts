import { describe, expect, it } from 'vitest';
import { AccountUpdate, Mina, UInt64 } from 'o1js';
import * as policy from './policy.js';
import { PROOFS_ON } from './proofs-on.js';
import { RequestProgram } from './request.js';
import { Vault, batchReducer } from './vault.js';
import { WithdrawalProgram } from './withdrawal.js';
import { VaultKeeper, actions } from './vault-view.js';
import { vaultHarness } from './vault-harness.js';

const [SMALL] = policy.DEPOSIT_SIZES;
const MINA = 1_000_000_000n;
// A reduce takes this many action lists itself; the rest need a recursive proof (`maxUpdatesFinalProof`).
const LIMIT = batchReducer.maxUpdatesFinalProof;

// Deposits are dispatched with proofs off; proofs go on for the reduces.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);

const { payer, bob, freshVault } = vaultHarness(Local);

describe('a vault with more action lists pending than a reduce takes', () => {
  it(PROOFS_ON.reduceLimit, async () => {
    // The vault is deployed with proofs on, so it carries the real key its reduces are checked against.
    await RequestProgram.compile();
    await WithdrawalProgram.compile();
    await batchReducer.compile();
    await Vault.compile();
    Local.setProofsEnabled(true);
    try {
      const h = await freshVault();
      Local.setProofsEnabled(false);
      // 101 deposits of 10 MINA outrun the payer's funds.
      const topUp = await Mina.transaction(bob, async () => {
        AccountUpdate.createSigned(bob).send({ to: payer, amount: UInt64.from(500n * MINA) });
      });
      await topUp.sign([bob.key]).send();

      const keeper = new VaultKeeper();
      keeper.track(h.vault.address);
      const reducedAll = async () =>
        (await actions(h.vault.address)).length === (await actions(h.vault.address, h.vault.actionState.get())).length;
      const deposits = async (n: number) => {
        for (let i = 0; i < n; i++) await h.deposit(SMALL);
      };

      // Within the limit: a reduce that doesn't recurse still works.
      await deposits(3);
      Local.setProofsEnabled(true);
      await keeper.reduce(h.vault, payer);
      expect(await reducedAll()).toBe(true);

     
      // Past the limit: the keeper has to prove the lists the reduce leaves out.
      Local.setProofsEnabled(false);
      await deposits(LIMIT + 1);
      Local.setProofsEnabled(true);
      expect(await reducedAll()).toBe(false);
      // Every batch carries the same action-stack proof and takes the same `verifyIf` path, so the first
      // reduce is proved for real and the rest, 25 more, are sent with proofs off.
      await keeper.reduce(h.vault, payer, (i) => Local.setProofsEnabled(i === 0));
      expect(await reducedAll()).toBe(true);
    } finally {
      Local.setProofsEnabled(false);
    }
  }, 7_200_000);
});
