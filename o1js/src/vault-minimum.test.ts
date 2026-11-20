// A generation's minimum withdrawal follows the fork's fee (ADR 0015): a close or escape dispatched under a lower minimum
// whose payout is now below it goes to the treasury at the reduce, and a new close needs the current minimum.
import { beforeAll, describe, expect, it } from 'vitest';
import { Mina, UInt64, Unconstrained } from 'o1js';
import * as policy from './policy.js';
import { balanceOf, now, vaultHarness } from './vault-harness.js';
import { RequestProgram } from './request.js';
import { WithdrawalKind, WithdrawalProgram } from './withdrawal.js';
import { batchReducer, vaultBuild } from './vault.js';
import { provableBatches } from './vault-view.js';

const [SMALL] = policy.DEPOSIT_SIZES;
const MINA = 1_000_000_000n;
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
WithdrawalProgram.setProofsEnabled(false);
RequestProgram.setProofsEnabled(false);
const { payer, alice, bob, advance, freshVault } = vaultHarness(Local);

/** The current generation's slot counts, with a minimum withdrawal a fork raised to 2 MINA. */
const RAISED = 2n * MINA;
const Raised = vaultBuild({ ...policy.generationOf('mesa-raised', policy.CURRENT_GENERATION.slotSeconds, RAISED) });

beforeAll(async () => {
  await batchReducer.compile();
});

/** Reduces `h`'s pending actions with the raised build, as a keeper running the re-keyed vault would. */
async function reduceRaised(h: Awaited<ReturnType<typeof freshVault>>) {
  const vault = new Raised.Vault(h.vault.address);
  batchReducer.setContractInstance(vault);
  for (const { batch, proof } of await provableBatches()) {
    const t = now();
    const { witnesses, nullifiers, escapes } = h.mirror.nextReduce(t);
    await h.send(
      await Mina.transaction(payer, async () => {
        await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(t));
      })
    );
  }
}

describe('a generation\'s minimum withdrawal', () => {
  it('keeps the account creation fee unless a generation is given another', () => {
    expect(policy.CURRENT_GENERATION.minWithdrawal).toBe(policy.ACCOUNT_CREATION_FEE);
    expect(policy.generationOf('x', 90n, RAISED).minWithdrawal).toBe(RAISED);
    expect(policy.generationOf('x', 90n, RAISED)).toEqual({ ...policy.generationOf('x', 90n), minWithdrawal: RAISED });
  });

  it('pays the treasury a pending escape\'s payout between the old and the new minimum, and applies the actions behind it', async () => {
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    // Dispatched under the 1 MINA minimum: it pays 1.5 MINA.
    const proof = await h.withdrawalProof(note, {
      kind: WithdrawalKind.escape, signed: true, step: 1, balance: 3n * MINA, conceded: 3n * MINA / 2n, destination: alice,
    });
    await h.escape(proof);
    await h.reduce();
    const nullifier = proof.publicInput.nullifier;
    const escape = h.mirror.pendingEscape(nullifier)!;
    expect(escape.payout().toBigInt()).toBe(3n * MINA / 2n);
    advance(escape.deadline.toBigInt() - now());
    await h.finalize(nullifier);
    const behind = await h.deposit(SMALL);

    const [toAlice, toTreasury] = [balanceOf(alice), balanceOf(h.treasury)];
    const next = h.vault.nextLeafIndex.get().toBigInt();
    await reduceRaised(h);
    expect(balanceOf(alice)).toBe(toAlice);
    expect(balanceOf(h.treasury)).toBe(toTreasury + SMALL);
    expect(h.mirror.pendingEscape(nullifier)).toBeUndefined();
    // The deposit queued behind the finalize landed in the tree.
    expect(h.vault.nextLeafIndex.get().toBigInt()).toBe(next + 1n);
    expect(behind.size).toBe(SMALL);
  });

  it('pays a payout dispatched below the new minimum from a close to the treasury, and one at it to the destination', async () => {
    const h = await freshVault();
    const [low, at] = [await h.deposit(SMALL), await h.deposit(SMALL)];
    await h.reduce();
    const below = await h.withdrawalProof(low, { signed: true, balance: 3n * MINA / 2n, destination: alice });
    await h.close(below);
    const atMin = await h.withdrawalProof(at, { signed: true, balance: RAISED, destination: bob });
    await h.close(atMin);
    const [toAlice, toBob, toTreasury] = [balanceOf(alice), balanceOf(bob), balanceOf(h.treasury)];
    await reduceRaised(h);
    expect(balanceOf(alice)).toBe(toAlice);
    expect(balanceOf(bob)).toBe(toBob + RAISED);
    expect(balanceOf(h.treasury)).toBe(toTreasury + SMALL + SMALL - RAISED);
  });

  it('refuses a new close or escape below the generation\'s minimum', async () => {
    const h = await freshVault({ build: Raised.Vault, minWithdrawal: RAISED });
    const note = await h.deposit(SMALL);
    await h.reduce();
    const low = await h.withdrawalProof(note, { signed: true, balance: RAISED - 1n, destination: alice });
    await expect(h.close(low)).rejects.toThrow(/payout below the minimum withdrawal/);
    const lowEscape = await h.withdrawalProof(note, {
      kind: WithdrawalKind.escape, signed: true, step: 1, balance: 3n * MINA, conceded: 3n * MINA - RAISED + 1n, destination: alice,
    });
    await expect(h.escape(lowEscape)).rejects.toThrow(/payout below the minimum withdrawal/);

    const ok = await h.withdrawalProof(note, { signed: true, balance: RAISED, destination: alice });
    const before = balanceOf(alice);
    await h.close(ok);
    await h.reduce();
    expect(balanceOf(alice)).toBe(before + RAISED);
  });
});
