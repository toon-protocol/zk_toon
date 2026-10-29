// Challenging an escape with a request proof as evidence (#10): a defeat at the escape's next
// nullifier cancels it, and a raise at its current nullifier lifts its concession to
// min(claimed, b, balance) (ADR 0004).
import { beforeAll, describe, expect, it } from 'vitest';
import { Bool, Mina, UInt64 } from 'o1js';
import * as policy from './policy.js';
import { PendingEscape, Vault, batchReducer } from './vault.js';
import { balanceOf, now, vaultHarness } from './vault-harness.js';
import { pendingEscapesView } from './vault-view.js';
import { RequestProgram, RequestProof, RequestPublic } from './request.js';
import { WithdrawalKind, WithdrawalProgram, type WithdrawalProof } from './withdrawal.js';

const [SMALL] = policy.DEPOSIT_SIZES;
const [, , TOP_TIER] = policy.TIERS;
const MINA = 1_000_000_000n;
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

/**
 * A reduced note, escaped from its state at `step` (0 is genesis) with `balance`, conceding `conceded`
 * to `destination`, and the escape recorded by a reduce.
 */
async function recordedEscape(h: Harness, o: { step?: number; balance?: bigint; conceded?: bigint } = {}) {
  const note = await h.deposit(SMALL);
  await h.reduce();
  const step = o.step ?? 1;
  const balance = step === 0 ? SMALL : o.balance ?? 3n * MINA;
  const proof = await h.withdrawalProof(note, {
    kind: ESCAPE, signed: step > 0, step, balance, conceded: o.conceded ?? 0n, destination: alice,
  });
  await h.escape(proof);
  await h.reduce();
  return { note, proof, step, balance, pending: () => h.mirror.pendingEscape(proof.publicInput.nullifier) };
}

/** Advances past the escape's deadline, finalizes it and reduces. */
async function finalizeAfterWindow(h: Harness, proof: WithdrawalProof) {
  advance(h.mirror.pendingEscape(proof.publicInput.nullifier)!.deadline.toBigInt() - now());
  await h.finalize(proof.publicInput.nullifier);
  await h.reduce();
}

describe('defeating an escape', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await freshVault();
  });

  it('with a request proof at the next nullifier cancels the escape, pays nothing, and the note goes on from its successor', async () => {
    const { note, proof } = await recordedEscape(h, { step: 0 });
    const [a, t, v] = [balanceOf(alice), balanceOf(h.treasury), balanceOf(h.vault.address)];
    // The note's successor (state 1) opened an allowance: the escape from genesis was stale.
    const evidence = await h.requestProof(note, { step: 1, balance: 4n * MINA, tier: TOP_TIER });
    expect(evidence.publicInput.nullifier.toBigInt()).toBe(proof.publicInput.nextNullifier.toBigInt());
    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    await h.defeat(proof.publicInput.nullifier, evidence);
    // Defeat only dispatches: the escape is still pending until the reduce.
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)).toBeDefined();
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)).toBeUndefined();
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());

    // A defeated escape never finalizes, and the deposit stays in the vault.
    advance(pending.deadline.toBigInt() - now());
    await expect(h.finalizeTx(pending)).rejects.toThrow(/no such pending escape/);
    expect([balanceOf(alice), balanceOf(h.treasury), balanceOf(h.vault.address)]).toEqual([a, t, v]);

    // Back to active: the zk edge's next signed state (state 2) closes like any other.
    const close = await h.withdrawalProof(note, { signed: true, step: 2, balance: 4n * MINA - MINA / 2n, destination: bob });
    const b = balanceOf(bob);
    await h.close(close);
    await h.reduce();
    expect(balanceOf(bob)).toBe(b + 4n * MINA - MINA / 2n);
    expect(balanceOf(h.treasury)).toBe(t + SMALL - (4n * MINA - MINA / 2n));
  });

  it('accepts a subsidised request proof at the next nullifier (ADR 0001)', async () => {
    const { note, proof } = await recordedEscape(h);
    const evidence = subsidised(await h.requestProof(note, { step: 2, tier: policy.TIERS[0] }));
    await h.defeat(proof.publicInput.nullifier, evidence);
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)).toBeUndefined();
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());
  });
});

describe('raising an escape', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await freshVault();
  });

  it('lifts the concession to the claimed charge when it is below b, and finalize pays balance − charge', async () => {
    const { note, proof, balance } = await recordedEscape(h, { conceded: MINA / 100n });
    const evidence = await h.requestProof(note, { balance, tier: TOP_TIER });
    expect(evidence.publicInput.nullifier.toBigInt()).toBe(proof.publicInput.nullifier.toBigInt());
    const charge = MINA / 2n;
    await h.raise(proof.publicInput.nullifier, evidence, charge);
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)!.conceded.toBigInt()).toBe(charge);
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());

    const [a, t] = [balanceOf(alice), balanceOf(h.treasury)];
    await finalizeAfterWindow(h, proof);
    expect(balanceOf(alice)).toBe(a + balance - charge);
    expect(balanceOf(h.treasury)).toBe(t + SMALL - (balance - charge));
  });

  it('caps the concession at the tier b when more is claimed', async () => {
    const { note, proof, balance } = await recordedEscape(h, { step: 0 });
    const evidence = await h.requestProof(note, { step: 0, tier: TOP_TIER });
    await h.raise(proof.publicInput.nullifier, evidence, 5n * MINA);
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)!.conceded.toBigInt()).toBe(TOP_TIER);
    const a = balanceOf(alice);
    await finalizeAfterWindow(h, proof);
    expect(balanceOf(alice)).toBe(a + balance - TOP_TIER);
  });

  it('refuses a raise that would not increase the concession', async () => {
    const { note, proof, balance } = await recordedEscape(h, { conceded: MINA / 2n });
    const evidence = await h.requestProof(note, { balance, tier: TOP_TIER });
    for (const claimed of [MINA / 4n, MINA / 2n]) {
      await expect(h.raiseTx(h.mirror.pendingEscape(proof.publicInput.nullifier)!, evidence, claimed))
        .rejects.toThrow(/would not increase the concession/);
    }
    // A smaller tier caps the claim below the concession too.
    const small = await h.requestProof(note, { balance, tier: policy.TIERS[1] });
    await expect(h.raiseTx(h.mirror.pendingEscape(proof.publicInput.nullifier)!, small, MINA))
      .rejects.toThrow(/would not increase the concession/);
  });

  it('refuses a raise from a subsidised request proof (ADR 0001)', async () => {
    const { note, proof, balance } = await recordedEscape(h);
    const evidence = subsidised(await h.requestProof(note, { balance, tier: policy.TIERS[0] }));
    await expect(h.raiseTx(h.mirror.pendingEscape(proof.publicInput.nullifier)!, evidence, policy.TIERS[0]))
      .rejects.toThrow(/would not increase the concession/);
  });

  it('applies two raises in one reduce only as far as the first: the second names a record already replaced', async () => {
    const { note, proof, balance } = await recordedEscape(h);
    const evidence = await h.requestProof(note, { balance, tier: TOP_TIER });
    await h.raise(proof.publicInput.nullifier, evidence, MINA / 4n);
    await h.raise(proof.publicInput.nullifier, evidence, MINA / 2n);
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)!.conceded.toBigInt()).toBe(MINA / 4n);
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());
    // A later raise from the record as it now stands lifts it again.
    await h.raise(proof.publicInput.nullifier, evidence, MINA / 2n);
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)!.conceded.toBigInt()).toBe(MINA / 2n);
  });

  it('a raise and a defeat dispatched before one reduce: the first wins, and the second is skipped', async () => {
    const { note, proof, balance } = await recordedEscape(h);
    const raiseEvidence = await h.requestProof(note, { balance, tier: TOP_TIER });
    const defeatEvidence = await h.requestProof(note, { step: 2, tier: TOP_TIER });
    await h.raise(proof.publicInput.nullifier, raiseEvidence, MINA / 2n);
    await h.defeat(proof.publicInput.nullifier, defeatEvidence);
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)!.conceded.toBigInt()).toBe(MINA / 2n);
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());
    // The defeat, sent again against the raised record, cancels the escape.
    await h.defeat(proof.publicInput.nullifier, defeatEvidence);
    await h.reduce();
    expect(h.mirror.pendingEscape(proof.publicInput.nullifier)).toBeUndefined();
  });
});

describe('evidence at another nullifier', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await freshVault();
  });

  it('is refused for a defeat: the current nullifier, a later state, or another note', async () => {
    const { note, proof, balance } = await recordedEscape(h);
    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    const other = await h.deposit(SMALL);
    await h.reduce();
    for (const evidence of [
      await h.requestProof(note, { balance, tier: TOP_TIER }),
      await h.requestProof(note, { step: 3, tier: TOP_TIER }),
      await h.requestProof(other, { step: 2, tier: TOP_TIER }),
    ]) {
      await expect(h.defeatTx(pending, evidence)).rejects.toThrow(/not the escape's next nullifier/);
    }
  });

  it('is refused for a raise: the next nullifier, an earlier state, or another note', async () => {
    const { note, proof, balance } = await recordedEscape(h);
    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    const other = await h.deposit(SMALL);
    await h.reduce();
    for (const evidence of [
      await h.requestProof(note, { step: 2, tier: TOP_TIER }),
      await h.requestProof(note, { step: 0, tier: TOP_TIER }),
      await h.requestProof(other, { balance, tier: TOP_TIER }),
    ]) {
      await expect(h.raiseTx(pending, evidence, MINA)).rejects.toThrow(/not the escape's nullifier/);
    }
  });

  it('is refused under another state key, and for an escape that is not pending', async () => {
    const { note, proof, balance } = await recordedEscape(h);
    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    const foreign = await h.requestProof(note, { balance, tier: TOP_TIER, foreignKey: true });
    await expect(h.raiseTx(pending, foreign, MINA)).rejects.toThrow(/not the vault state key/);
    const evidence = await h.requestProof(note, { balance, tier: TOP_TIER });
    const misnamed = new PendingEscape({ ...pending, conceded: UInt64.from(1n) });
    await expect(h.raiseTx(misnamed, evidence, MINA)).rejects.toThrow(/no such pending escape/);
    const successor = await h.requestProof(note, { step: 2, tier: TOP_TIER });
    await expect(h.defeatTx(misnamed, successor)).rejects.toThrow(/no such pending escape/);
  });
});

// Their own vault, since LocalBlockchain records the actions of a transaction its preconditions reject.
describe('challenge timing', () => {
  it('refuses a defeat or a raise once the window ends, and accepts them a slot before', async () => {
    const h = await freshVault();
    const { note, proof, balance } = await recordedEscape(h);
    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    const raiseEvidence = await h.requestProof(note, { balance, tier: TOP_TIER });
    const defeatEvidence = await h.requestProof(note, { step: 2, tier: TOP_TIER });
    advance(pending.deadline.toBigInt() - now() - 2n * 90_000n);
    expect(now()).toBeLessThan(pending.deadline.toBigInt());
    await h.send(await h.raiseTx(pending, raiseEvidence, MINA));
    await h.send(await h.defeatTx(pending, defeatEvidence));
    advance(pending.deadline.toBigInt() - now());
    await expect(h.send(await h.raiseTx(pending, raiseEvidence, MINA))).rejects.toThrow(/Protocol_state_precondition_unsatisfied/);
    await expect(h.send(await h.defeatTx(pending, defeatEvidence))).rejects.toThrow(/Protocol_state_precondition_unsatisfied/);
  });
});

describe("the vault's escape events", () => {
  it('rebuild its pending escapes to its root, with each deadline and raise as the reduce recorded it', async () => {
    const h = await freshVault();
    const raised = await recordedEscape(h, { conceded: MINA / 100n });
    const defeated = await recordedEscape(h, { step: 0 });
    const finalized = await recordedEscape(h);
    const raisedAt = raised.proof.publicInput.nullifier;
    await h.raise(raisedAt, await h.requestProof(raised.note, { balance: raised.balance, tier: TOP_TIER }), MINA / 2n);
    await h.defeat(
      defeated.proof.publicInput.nullifier,
      await h.requestProof(defeated.note, { step: 1, balance: 4n * MINA, tier: TOP_TIER })
    );
    await h.reduce();
    await finalizeAfterWindow(h, finalized.proof);

    const view = await pendingEscapesView(h.vault, { localChain: true });
    expect(view.escapes.root.toBigInt()).toBe(h.vault.pendingEscapesRoot.get().toBigInt());
    expect([...view.records.keys()]).toEqual([raisedAt.toBigInt()]);
    const record = view.records.get(raisedAt.toBigInt())!;
    expect(record.conceded.toBigInt()).toBe(MINA / 2n);
    expect(PendingEscape.toJSON(record)).toEqual(PendingEscape.toJSON(h.mirror.pendingEscape(raisedAt)!));
  });

  it('rebuild escapes recorded together by one reduce, in the order it recorded them', async () => {
    const h = await freshVault();
    const notes = [await h.deposit(SMALL), await h.deposit(SMALL)];
    await h.reduce();
    for (const note of notes) {
      await h.escape(await h.withdrawalProof(note, {
        kind: ESCAPE, signed: true, step: 1, balance: 3n * MINA, conceded: 0n, destination: alice,
      }));
    }
    await h.reduce();
    const view = await pendingEscapesView(h.vault, { localChain: true });
    expect(view.escapes.root.toBigInt()).toBe(h.vault.pendingEscapesRoot.get().toBigInt());
    expect(view.records.size).toBe(2);
  });
});

describe('the reduce with challenges', () => {
  it('fits in one circuit', async () => {
    const { reduce } = await Vault.analyzeMethods();
    expect(reduce.rows).toBeLessThanOrEqual(2 ** 16);
  });
});

/** The same evidence, as if the payer had proved it subsidised (only the public input matters with proofs off). */
function subsidised(p: RequestProof): RequestProof {
  return new RequestProof({ ...p, publicInput: new RequestPublic({ ...p.publicInput, subsidised: Bool(true) }) });
}
