import { beforeAll, describe, expect, it } from 'vitest';
import { Mina } from 'o1js';
import * as policy from './policy.js';
import { balanceOf, now, vaultHarness } from './vault-harness.js';
import { RequestProgram } from './request.js';
import { WithdrawalKind, WithdrawalProgram } from './withdrawal.js';
import { batchReducer, vaultBuild } from './vault.js';

const [SMALL] = policy.DEPOSIT_SIZES;
const MINA = 1_000_000_000n;
const WINDOW = policy.CHALLENGE_WINDOW_SLOTS;
const TOP_TIER = policy.TIERS[policy.TIERS.length - 1];

const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
WithdrawalProgram.setProofsEnabled(false);
RequestProgram.setProofsEnabled(false);
const { payer, alice, advance, freshVault } = vaultHarness(Local);

/** A build for fork 1. A vault registered through the registry records fork 0, as a re-keyed vault's state would. */
const Fork1 = vaultBuild(1n);
/** A build for fork 1 whose `init` records fork 1, as a new vault's does. */
const NewFork1 = vaultBuild(1n);


beforeAll(async () => {
  await batchReducer.compile();
});

/** A recorded escape of a note, its pending record and the slot of its deadline. */
async function pendingEscape(h: Awaited<ReturnType<typeof freshVault>>, step = 1) {
  const note = await h.deposit(SMALL);
  await h.reduce();
  const proof = await h.withdrawalProof(note, { kind: WithdrawalKind.escape, signed: step > 0, step, balance: step === 0 ? SMALL : 3n * MINA, destination: alice });
  await h.escape(proof);
  await h.reduce();
  const nullifier = proof.publicInput.nullifier;
  return { note, nullifier, deadline: h.mirror.pendingEscape(nullifier)!.deadline.toBigInt() };
}

describe('resume (ADR 0015)', () => {
  it('holds back finalize from a vault behind the build\'s fork until a window after its resume', async () => {
    const h = await freshVault({ build: Fork1 });
    expect(h.vault.forkResumed.get().toBigInt()).toBe(0n);
    const { nullifier, deadline } = await pendingEscape(h);
    advance(deadline - now());
    await expect(h.finalizeTx(h.mirror.pendingEscape(nullifier)!)).rejects.toThrow(/has not resumed/);

    await h.send(await Mina.transaction(payer, async () => { await h.vault.resume(); }));
    expect(h.vault.forkResumed.get().toBigInt()).toBe(1n);
    const resumedAt = h.vault.resumedAt.get().toBigInt();
    expect(resumedAt).toBeGreaterThanOrEqual(now());

    // The same block as the resume: nothing finalizes, however far its deadline is past.
    await expect(h.send(await h.finalizeTx(h.mirror.pendingEscape(nullifier)!))).rejects.toThrow();
    advance(resumedAt + WINDOW - 1n - now());
    await expect(h.send(await h.finalizeTx(h.mirror.pendingEscape(nullifier)!))).rejects.toThrow();
  });

  it('finalizes a window after the resume', async () => {
    const h = await freshVault({ build: Fork1 });
    const { nullifier, deadline } = await pendingEscape(h);
    advance(deadline - now());
    await h.send(await Mina.transaction(payer, async () => { await h.vault.resume(); }));
    advance(WINDOW + 1n);
    const before = balanceOf(alice);
    await h.finalize(nullifier);
    await h.reduce();
    expect(balanceOf(alice)).toBe(before + 3n * MINA);
  });

  it('refuses a second resume', async () => {
    const h = await freshVault({ build: Fork1 });
    await h.send(await Mina.transaction(payer, async () => { await h.vault.resume(); }));
    advance(1n);
    await expect(Mina.transaction(payer, async () => { await h.vault.resume(); })).rejects.toThrow(/not behind this fork/);
  });

  it('refuses a resume on a new vault, and finalizes it with no resume', async () => {
    const h = await freshVault({ build: NewFork1, direct: true });
    expect(h.vault.forkResumed.get().toBigInt()).toBe(1n);
    await expect(Mina.transaction(payer, async () => { await h.vault.resume(); })).rejects.toThrow(/not behind this fork/);
    const { nullifier, deadline } = await pendingEscape(h);
    advance(deadline - now());
    await h.finalize(nullifier);
  });

  it('refuses a resume on a vault of the fork-0 build', async () => {
    const h = await freshVault();
    await expect(Mina.transaction(payer, async () => { await h.vault.resume(); })).rejects.toThrow(/not behind this fork/);
  });

  it('lets a defeat and a raise land before the resume', async () => {
    const h = await freshVault({ build: Fork1 });
    const defeated = await pendingEscape(h, 0);
    await h.defeat(defeated.nullifier, await h.requestProof(defeated.note, { step: 1, balance: 4n * MINA, tier: TOP_TIER }));
    await h.reduce();
    const raised = await pendingEscape(h);
    await h.raise(raised.nullifier, await h.requestProof(raised.note, { balance: 3n * MINA, tier: TOP_TIER }), MINA / 2n);
    await h.reduce();
  });
});
