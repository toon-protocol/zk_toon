// The expiry sweep (#11, ADR 0005): once notes expire, anyone may walk the note tree in index order and
// sweep to the treasury what the expired notes left in the vault, without naming any one note's fate.
// A sweep pays `expired − claimed − swept`, never less than zero, where `claimed` is the sizes of notes
// withdrawn or with a pending escape. It underpays until withdrawn notes also expire.
import { beforeAll, describe, expect, it } from 'vitest';
import { Mina } from 'o1js';
import * as policy from './policy.js';
import { CLOSE_WINDOW_SLOTS, SWEEP_BATCH_SIZE, Vault, batchReducer } from './vault.js';
import { balanceOf, now, vaultHarness, type Note } from './vault-harness.js';
import { RequestProgram } from './request.js';
import { WithdrawalKind, WithdrawalProgram } from './withdrawal.js';

const [SMALL, MEDIUM] = policy.DEPOSIT_SIZES;
const [, , TOP_TIER] = policy.TIERS;
const MINA = 1_000_000_000n;
const LIFETIME = policy.NOTE_LIFETIME_SLOTS;
const { escape: ESCAPE } = WithdrawalKind;

// Proofs off: the contract logic runs, but no circuit is proven.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
WithdrawalProgram.setProofsEnabled(false);
RequestProgram.setProofsEnabled(false);

const { alice, bob, advance, freshVault } = vaultHarness(Local);
type Harness = Awaited<ReturnType<typeof freshVault>>;

beforeAll(async () => {
  await batchReducer.compile();
});

/** The slot from which a sweep may count `note`: its expiry, plus the window a close may still land in. */
const sweepableAt = (note: Note) => note.depositTime + LIFETIME + CLOSE_WINDOW_SLOTS;
/** Moves the chain to slot `t`, or not at all if it is already there. */
const advanceTo = (t: bigint) => {
  if (t > now()) advance(t - now());
};
const holdings = (h: Harness) => [balanceOf(h.treasury), balanceOf(h.vault.address)];

describe('an expiry sweep', () => {
  it('is refused before any note has expired', async () => {
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    await expect(h.sweepTx(0)).rejects.toThrow(/nothing has expired/);
    await expect(h.sweepTx(1)).rejects.toThrow(/note not expired/);
    // Expired, but a close proven just before expiry may still land: not yet.
    advanceTo(note.depositTime + LIFETIME);
    await expect(h.sweepTx(1)).rejects.toThrow(/note not expired/);
    advanceTo(sweepableAt(note));
    await h.sweep();
  });

  it('pays the unwithdrawn deposits of expired notes to the treasury, once', async () => {
    const h = await freshVault();
    const [a, b] = [await h.deposit(SMALL), await h.deposit(MEDIUM)];
    await h.reduce();
    advanceTo(sweepableAt(b));
    const [t, v] = holdings(h);
    await h.sweep();
    // The sweep only dispatches; the reduce pays.
    expect(holdings(h)).toEqual([t, v]);
    await h.reduce();
    expect(holdings(h)).toEqual([t + SMALL + MEDIUM, v - SMALL - MEDIUM]);
    expect(h.vault.sweepCursor.get().toBigInt()).toBe(2n);
    expect(a.depositTime).toBeLessThanOrEqual(b.depositTime);

    // Nothing new has expired, and nothing is swept twice.
    await h.sweep({ count: 0 });
    await h.reduce();
    expect(holdings(h)).toEqual([t + SMALL + MEDIUM, v - SMALL - MEDIUM]);
  });

  it('walks at most a batch of notes per call, in index order', async () => {
    const h = await freshVault();
    const notes: Note[] = [];
    for (let i = 0; i <= SWEEP_BATCH_SIZE; i++) notes.push(await h.deposit(SMALL));
    await h.reduce();
    advanceTo(sweepableAt(notes[SWEEP_BATCH_SIZE]));
    const [t] = holdings(h);
    await h.sweep();
    await h.reduce();
    expect(balanceOf(h.treasury)).toBe(t + BigInt(SWEEP_BATCH_SIZE) * SMALL);
    await h.sweep();
    await h.reduce();
    expect(balanceOf(h.treasury)).toBe(t + BigInt(SWEEP_BATCH_SIZE + 1) * SMALL);
  });

  it('refuses to count a note that is not the next in the tree', async () => {
    const h = await freshVault();
    const notes = [await h.deposit(SMALL), await h.deposit(SMALL)];
    await h.reduce();
    advanceTo(sweepableAt(notes[1]));
    // The note at index 1 offered as if at the cursor (0).
    await expect(h.sweepTx(1, { from: 1n })).rejects.toThrow(/not the note at the sweep cursor/);
  });

  it('waits for a note with a later deposit slot than the note after it', async () => {
    const h = await freshVault();
    // Deposit slots may run up to a slot out of index order: a deposit names a slot up to a slot old.
    const first = await h.deposit(SMALL);
    const second = await h.deposit(SMALL, { depositTime: first.depositTime - 1n });
    await h.reduce();
    advanceTo(sweepableAt(second));
    expect(now()).toBeLessThan(sweepableAt(first));
    await expect(h.sweepTx(2)).rejects.toThrow(/note not expired/);
    advanceTo(sweepableAt(first));
    const [t] = holdings(h);
    await h.sweep();
    await h.reduce();
    expect(balanceOf(h.treasury)).toBe(t + 2n * SMALL);
  });
});

describe('a sweep never takes money that can still be claimed', () => {
  it('leaves a live note, which then closes in full', async () => {
    const h = await freshVault();
    const old = await h.deposit(SMALL);
    await h.reduce();
    advance(30n * policy.SLOTS_PER_DAY);
    const live = await h.deposit(MEDIUM);
    await h.reduce();
    advanceTo(sweepableAt(old));
    const [t, v] = holdings(h);
    await h.sweep();
    await h.reduce();
    expect(holdings(h)).toEqual([t + SMALL, v - SMALL]);

    const a = balanceOf(alice);
    await h.close(await h.withdrawalProof(live, { signed: true, balance: 40n * MINA, destination: alice }));
    await h.reduce();
    expect(balanceOf(alice)).toBe(a + 40n * MINA);
    expect(holdings(h)).toEqual([t + SMALL + MEDIUM - 40n * MINA, v - SMALL - MEDIUM]);
  });

  it('leaves a deposit not yet reduced', async () => {
    const h = await freshVault();
    const old = await h.deposit(SMALL);
    await h.reduce();
    advanceTo(sweepableAt(old));
    const [t, v] = holdings(h);
    const fresh = await h.deposit(MEDIUM);
    await h.sweep();
    await h.reduce();
    expect(holdings(h)).toEqual([t + SMALL, v + MEDIUM - SMALL]);
    expect(h.mirror.tree.nextIndex).toBe(2n);
    expect(fresh.size).toBe(MEDIUM);
  });

  it('leaves a close proven before expiry, landing after it and reduced after the sweep, which is paid', async () => {
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    const expiry = note.depositTime + LIFETIME;
    advanceTo(expiry);
    const close = await h.withdrawalProof(note, { signed: true, balance: 4n * MINA, destination: alice, requestTime: expiry - 1n });
    // The close may still land, so the sweep may not yet count the note.
    await expect(h.sweepTx(1)).rejects.toThrow(/note not expired/);
    await h.close(close);
    advanceTo(sweepableAt(note));
    const [a, [t, v]] = [balanceOf(alice), holdings(h)];
    await h.sweep();
    await h.reduce();
    expect(balanceOf(alice)).toBe(a + 4n * MINA);
    expect(holdings(h)).toEqual([t + SMALL - 4n * MINA, v - SMALL]);
  });

  it('underpays while a withdrawn note is unexpired, and never sweeps its size', async () => {
    const h = await freshVault();
    const abandoned = await h.deposit(SMALL);
    await h.reduce();
    advance(30n * policy.SLOTS_PER_DAY);
    const closed = await h.deposit(SMALL);
    await h.reduce();
    await h.close(await h.withdrawalProof(closed, { destination: bob }));
    await h.reduce();

    // The abandoned note has expired, the closed one has not: its withdrawal holds the sweep back.
    advanceTo(sweepableAt(abandoned));
    const [t, v] = holdings(h);
    await h.sweep();
    await h.reduce();
    expect(holdings(h)).toEqual([t, v]);

    // Once the closed note expires too, the abandoned deposit is swept, and the closed one's is not.
    advanceTo(sweepableAt(closed));
    await h.sweep();
    await h.reduce();
    expect(holdings(h)).toEqual([t + SMALL, v - SMALL]);
    expect(v - SMALL).toBe(balanceOf(h.vault.address));
  });
});

describe('a pending escape at expiry', () => {
  /** A reduced note escaped from its signed state at step 1 a little before it expires, recorded by a reduce. */
  async function escapedNearExpiry(h: Harness) {
    const note = await h.deposit(SMALL);
    await h.reduce();
    advanceTo(note.depositTime + LIFETIME - 20n);
    const proof = await h.withdrawalProof(note, {
      kind: ESCAPE, signed: true, balance: 3n * MINA, conceded: MINA / 10n, destination: alice,
      validUntil: note.depositTime + LIFETIME - 1n,
    });
    // The challenger's evidence of the successor state, proven while the note was live.
    const evidence = await h.requestProof(note, { step: 2, tier: TOP_TIER });
    await h.escape(proof);
    await h.reduce();
    return { note, nullifier: proof.publicInput.nullifier, evidence };
  }

  it('is finalized by the escape rules, and the sweep leaves its funds', async () => {
    const h = await freshVault();
    const { note, nullifier } = await escapedNearExpiry(h);
    const pending = h.mirror.pendingEscape(nullifier)!;
    advanceTo(sweepableAt(note));
    expect(now()).toBeLessThan(pending.deadline.toBigInt());
    const [a, [t, v]] = [balanceOf(alice), holdings(h)];
    await h.sweep();
    await h.reduce();
    expect(holdings(h)).toEqual([t, v]);

    advanceTo(pending.deadline.toBigInt());
    await h.finalize(nullifier);
    await h.reduce();
    expect(balanceOf(alice)).toBe(a + 3n * MINA - MINA / 10n);
    expect(holdings(h)).toEqual([t + SMALL - 3n * MINA + MINA / 10n, v - SMALL]);
    // Finalized and expired: nothing more to sweep.
    await h.sweep({ count: 0 });
    await h.reduce();
    expect(holdings(h)).toEqual([t + SMALL - 3n * MINA + MINA / 10n, v - SMALL]);
  });

  it('once defeated, leaves its expired deposit to the next sweep', async () => {
    const h = await freshVault();
    const { note, nullifier, evidence } = await escapedNearExpiry(h);
    advanceTo(sweepableAt(note));
    const [t, v] = holdings(h);
    await h.sweep();
    await h.reduce();
    expect(holdings(h)).toEqual([t, v]);
    await h.defeat(nullifier, evidence);
    await h.reduce();
    await h.sweep({ count: 0 });
    await h.reduce();
    expect(holdings(h)).toEqual([t + SMALL, v - SMALL]);
  });
});

describe('the sweep', () => {
  it('fits in one circuit, and the reduce still does', async () => {
    const { reduce, sweepExpired } = await Vault.analyzeMethods();
    expect(reduce.rows).toBeLessThanOrEqual(2 ** 16);
    expect(sweepExpired.rows).toBeLessThanOrEqual(2 ** 16);
  });

  it('refuses before setup', async () => {
    const h = await freshVault({ setup: false });
    const note = await h.deposit(SMALL);
    await h.reduce();
    advanceTo(sweepableAt(note));
    await expect(h.sweepTx(1)).rejects.toThrow(/setup has not run/);
  });
});
