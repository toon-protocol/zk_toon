import { beforeAll, describe, expect, it } from 'vitest';
import { PROOFS_ON } from './proofs-on.js';
import { AccountUpdate, Bool, Field, Mina, Permissions, PrivateKey, UInt32, UInt64, VerificationKey, verify } from 'o1js';
import * as policy from './policy.js';
import { PendingEscape, SLOT_MS, VAULT_URI, batchReducer } from './vault.js';
import { balanceOf, now, vaultHarness } from './vault-harness.js';
import { WithdrawalKind, WithdrawalProgram, WithdrawalProof, WithdrawalPublic } from './withdrawal.js';

const [SMALL] = policy.DEPOSIT_SIZES;
const MINA = 1_000_000_000n;
const WINDOW = policy.CHALLENGE_WINDOW_MS;
const { escape: ESCAPE } = WithdrawalKind;

// Proofs off: the contract logic runs, but no circuit is proven, except where a test compiles one.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
WithdrawalProgram.setProofsEnabled(false);

const { payer, alice, bob, advance, freshVault } = vaultHarness(Local);
type Harness = Awaited<ReturnType<typeof freshVault>>;

beforeAll(async () => {
  await batchReducer.compile();
});

/** A reduced note of a signed state with `balance`, escaped to `destination` conceding `conceded`. */
async function escaped(h: Harness, o: { balance?: bigint; conceded?: bigint; destination?: typeof alice } = {}) {
  const note = await h.deposit(SMALL);
  await h.reduce();
  const proof = await h.withdrawalProof(note, {
    kind: ESCAPE, signed: true, balance: o.balance ?? 3n * MINA, conceded: o.conceded ?? 0n, destination: o.destination ?? alice,
  });
  await h.escape(proof);
  return { note, proof };
}

describe('vault escape and finalize', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await freshVault();
  });

  it('pays balance − conceded to the destination and the rest to the treasury, after the window', async () => {
    const [balance, conceded] = [3n * MINA, MINA / 10n];
    const before = [balanceOf(alice), balanceOf(h.treasury), balanceOf(h.vault.address)];
    const { proof } = await escaped(h, { balance, conceded });
    const deposited = [before[0], before[1], before[2] + SMALL];
    // The escape only dispatches; the reduce records it and starts the window, paying nothing.
    expect([balanceOf(alice), balanceOf(h.treasury), balanceOf(h.vault.address)]).toEqual(deposited);
    const recordedAt = now();
    await h.reduce();
    expect([balanceOf(alice), balanceOf(h.treasury), balanceOf(h.vault.address)]).toEqual(deposited);

    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());
    expect(pending.nextNullifier.toBigInt()).toBe(proof.publicInput.nextNullifier.toBigInt());
    expect([pending.amount.toBigInt(), pending.conceded.toBigInt(), pending.size.toBigInt()]).toEqual([balance, conceded, SMALL]);
    expect(pending.destination.toBase58()).toBe(alice.toBase58());
    expect(pending.deadline.toBigInt()).toBeGreaterThanOrEqual(recordedAt + WINDOW);

    advance(pending.deadline.toBigInt() - now());
    await h.finalize(proof.publicInput.nullifier, bob);
    expect(balanceOf(alice)).toBe(deposited[0]);
    await h.reduce();
    expect(balanceOf(alice)).toBe(before[0] + balance - conceded);
    expect(balanceOf(h.treasury)).toBe(before[1] + SMALL - (balance - conceded));
    expect(balanceOf(h.vault.address)).toBe(before[2]);
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());

    // A finalized escape is no longer pending: a second finalize is refused.
    const spent = new PendingEscape({ ...pending });
    await expect(h.finalizeTx(spent)).rejects.toThrow(/no such pending escape/);
  });

  it('pays a genesis note conceding nothing in full to the destination', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const proof = await h.withdrawalProof(note, { kind: ESCAPE, destination: bob });
    const [b, t] = [balanceOf(bob), balanceOf(h.treasury)];
    await h.escape(proof);
    await h.reduce();
    advance(h.mirror.pendingEscape(proof.publicInput.nullifier)!.deadline.toBigInt() - now());
    await h.finalize(proof.publicInput.nullifier);
    await h.reduce();
    expect(balanceOf(bob)).toBe(b + SMALL);
    expect(balanceOf(h.treasury)).toBe(t);
  });

  it('refuses to finalize an escape the vault never recorded', async () => {
    const { proof } = await escaped(h);
    // Not reduced yet: nothing is pending.
    const unrecorded = new PendingEscape({
      nullifier: proof.publicInput.nullifier, nextNullifier: proof.publicInput.nextNullifier, amount: UInt64.from(3n * MINA),
      conceded: UInt64.zero, size: UInt64.from(SMALL), destination: alice, deadline: UInt64.from(now()),
    });
    await expect(h.finalizeTx(unrecorded)).rejects.toThrow(/no such pending escape/);
    await h.reduce();
    // Recorded, but not with another destination.
    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    advance(pending.deadline.toBigInt() - now());
    const redirected = new PendingEscape({ ...pending, destination: bob });
    await expect(h.finalizeTx(redirected)).rejects.toThrow(/no such pending escape/);
    await h.finalize(proof.publicInput.nullifier);
    await h.reduce();
  });
});

describe('a note mid-escape', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await freshVault();
  });

  it('can be neither closed nor escaped again, at its current or next nullifier', async () => {
    const { note, proof } = await escaped(h);
    await h.reduce();
    const pub = proof.publicInput;
    for (const n of [pub.nullifier, pub.nextNullifier]) {
      expect(h.mirror.nullifiers.isIncluded(n).toBoolean()).toBe(true);
    }
    expect(h.vault.nullifierRoot.get().toBigInt()).toBe(h.mirror.nullifiers.root.toBigInt());
    const close = await h.withdrawalProof(note, { signed: true, balance: 3n * MINA });
    await expect(h.close(close)).rejects.toThrow(/nullifier spent/);
    const again = await h.withdrawalProof(note, { kind: ESCAPE, signed: true, balance: 3n * MINA, destination: bob });
    await expect(h.escape(again)).rejects.toThrow(/nullifier spent/);
  });

  it('dispatched with a close or a second escape before one reduce: only the first is recorded, and the close is not paid', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const escape = await h.withdrawalProof(note, { kind: ESCAPE, signed: true, balance: 2n * MINA, destination: alice });
    const second = await h.withdrawalProof(note, { kind: ESCAPE, signed: true, balance: 2n * MINA, destination: bob });
    const close = await h.withdrawalProof(note, { signed: true, balance: 2n * MINA, destination: bob });
    const [b, v] = [balanceOf(bob), balanceOf(h.vault.address)];
    await h.escape(escape);
    await h.escape(second);
    await h.close(close);
    await h.reduce();
    expect(balanceOf(bob)).toBe(b);
    expect(balanceOf(h.vault.address)).toBe(v);
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());
    expect(h.mirror.pendingEscape(escape.publicInput.nullifier)!.destination.toBase58()).toBe(alice.toBase58());

    // The escape that was recorded finalizes to its own destination.
    const a = balanceOf(alice);
    advance(h.mirror.pendingEscape(escape.publicInput.nullifier)!.deadline.toBigInt() - now());
    await h.finalize(escape.publicInput.nullifier);
    await h.reduce();
    expect(balanceOf(alice)).toBe(a + 2n * MINA);
    expect(balanceOf(bob)).toBe(b);
  });

  it('a close dispatched before an escape wins, and the escape is never recorded', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const close = await h.withdrawalProof(note, { destination: bob });
    const escape = await h.withdrawalProof(note, { kind: ESCAPE, destination: alice });
    const [a, b] = [balanceOf(alice), balanceOf(bob)];
    await h.close(close);
    await h.escape(escape);
    await h.reduce();
    expect(balanceOf(bob)).toBe(b + SMALL);
    expect(balanceOf(alice)).toBe(a);
    expect(h.mirror.pendingEscape(escape.publicInput.nullifier)).toBeUndefined();
    expect(h.vault.pendingEscapesRoot.get().toBigInt()).toBe(h.mirror.escapes.root.toBigInt());
  });
});

describe('vault escape refusals', () => {
  it('refuses an escape before setup', async () => {
    const h = await freshVault({ setup: false });
    const note = await h.deposit(SMALL);
    await h.reduce();
    await expect(h.escape(await h.withdrawalProof(note, { kind: ESCAPE }))).rejects.toThrow(/setup has not run/);
  });

  it('refuses another kind of proof, another state key, and a root not in the ring', async () => {
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    for (const kind of [WithdrawalKind.mutualClose, WithdrawalKind.ownership]) {
      await expect(h.escape(await h.withdrawalProof(note, { kind }))).rejects.toThrow(/not an escape/);
    }
    const foreign = await h.withdrawalProof(note, { kind: ESCAPE, signed: true, balance: MINA, key: PrivateKey.random() });
    await expect(h.escape(foreign)).rejects.toThrow(/state key/);
    const valid = await h.withdrawalProof(note, { kind: ESCAPE });
    const stale = new WithdrawalProof({ ...valid, publicInput: new WithdrawalPublic({ ...valid.publicInput, root: valid.publicInput.root.add(1) }) });
    await expect(h.escape(stale)).rejects.toThrow(/root not in the ring/);
  });
});

// Their own vaults, since LocalBlockchain records the actions of a transaction its preconditions
// reject: none of these vaults is reduced after a refusal.
describe('vault escape timing', () => {
  it('refuses an escape proof used after its validUntil, or before its requestTime', async () => {
    Local.incrementGlobalSlot(100);
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    const t = now();
    const expired = await h.withdrawalProof(note, { kind: ESCAPE, requestTime: t - 20n * policy.MS_PER_MINUTE, validUntil: t - 1n });
    await expect(h.send(await h.escapeTx(expired))).rejects.toThrow(/Protocol_state_precondition_unsatisfied/);
    const early = await h.withdrawalProof(note, { kind: ESCAPE, requestTime: t + 1n });
    await expect(h.send(await h.escapeTx(early))).rejects.toThrow(/Protocol_state_precondition_unsatisfied/);
    // At its validUntil, accepted.
    const last = await h.withdrawalProof(note, { kind: ESCAPE, requestTime: t - 20n * policy.MS_PER_MINUTE, validUntil: t });
    await h.send(await h.escapeTx(last));
  });

  it('refuses to finalize before the window ends', async () => {
    const h = await freshVault();
    const { proof } = await escaped(h);
    await h.reduce();
    const pending = h.mirror.pendingEscape(proof.publicInput.nullifier)!;
    const deadline = pending.deadline.toBigInt();
    await expect(h.send(await h.finalizeTx(pending))).rejects.toThrow(/Protocol_state_precondition_unsatisfied/);
    // A slot short of the deadline: still refused.
    advance(deadline - now() - SLOT_MS);
    expect(now()).toBeLessThan(deadline);
    await expect(h.send(await h.finalizeTx(pending))).rejects.toThrow(/Protocol_state_precondition_unsatisfied/);
    advance(deadline - now());
    await h.send(await h.finalizeTx(pending));
  });
});

describe('the vault has no pause', () => {
  it('refuses every owner change that could stop or delay an escape, and the escape still finalizes', async () => {
    const h = await freshVault();
    const { proof } = await escaped(h);
    // A signed update by the upgrade key, replay-protected by the full commitment so that it increments no nonce.
    const owner = async (change: (u: AccountUpdate) => void, incrementNonce = false) =>
      h.send(await Mina.transaction(payer, async () => {
        const u = AccountUpdate.createSigned(h.vault.address);
        if (!incrementNonce) {
          u.body.useFullCommitment = Bool(true);
          u.body.incrementNonce = Bool(false);
          u.body.preconditions.account.nonce.isSome = Bool(false);
          u.body.preconditions.account.nonce.value.lower = UInt32.zero;
          u.body.preconditions.account.nonce.value.upper = UInt32.MAXINT();
        }
        change(u);
      }), [h.zkappKey]);

    // The upgrade key can change nothing that touches funds or state, and nothing but the delegate.
    expect(Mina.getAccount(h.vault.address).zkapp!.zkappUri).toBe(VAULT_URI);
    await expect(owner((u) => u.account.zkappUri.set('https://example.org/other'))).rejects.toThrow(/zkappUri/);
    await expect(owner(() => {}, true)).rejects.toThrow(/incrementNonce/);
    await expect(owner((u) => u.account.votingFor.set(Field(1)))).rejects.toThrow(/votingFor/);
    await expect(owner((u) => u.account.tokenSymbol.set('X'))).rejects.toThrow(/tokenSymbol/);
    await expect(owner((u) => AccountUpdate.setValue(u.body.update.appState[0], Field(1)))).rejects.toThrow();
        await expect(owner((u) => u.account.verificationKey.set(VerificationKey.dummySync()))).rejects.toThrow();
    await expect(owner((u) => u.account.permissions.set(Permissions.allImpossible()))).rejects.toThrow();
    await expect(owner((u) => u.account.permissions.set(Permissions.default()))).rejects.toThrow();
    await expect(owner((u) => u.account.timing.set({
      initialMinimumBalance: UInt64.from(balanceOf(h.vault.address)), cliffTime: UInt32.from(10_000_000), cliffAmount: UInt64.zero,
      vestingPeriod: UInt32.one, vestingIncrement: UInt64.zero,
    }))).rejects.toThrow();
    await expect(owner((u) => u.send({ to: bob, amount: UInt64.from(MINA) }))).rejects.toThrow();

    // Staking is deliberate: the upgrade key may delegate, which moves no funds.
    await owner((u) => u.account.delegate.set(bob));
    expect(Mina.getAccount(h.vault.address).delegate?.toBase58()).toBe(bob.toBase58());

    await h.reduce();
    const a = balanceOf(alice);
    advance(h.mirror.pendingEscape(proof.publicInput.nullifier)!.deadline.toBigInt() - now());
    await h.finalize(proof.publicInput.nullifier);
    await h.reduce();
    expect(balanceOf(alice)).toBe(a + 3n * MINA);
  });
});

describe('vault escape with a real withdrawal proof', () => {
  it(PROOFS_ON.escape, async () => {
    const { verificationKey } = await WithdrawalProgram.compile({ proofsEnabled: true });
    WithdrawalProgram.setProofsEnabled(true);
    try {
      const h = await freshVault();
      const note = await h.deposit(SMALL);
      await h.reduce();
      const proof = await h.withdrawalProof(note, { kind: ESCAPE, signed: true, balance: 2n * MINA, conceded: MINA / 100n, destination: alice });
      expect(await verify(proof, verificationKey)).toBe(true);
      // Changing the destination invalidates the proof.
      const redirected = new WithdrawalProof({
        ...proof, publicInput: new WithdrawalPublic({ ...proof.publicInput, destination: bob }),
      });
      expect(await verify(redirected, verificationKey)).toBe(false);

      const a = balanceOf(alice);
      await h.escape(proof);
      await h.reduce();
      advance(h.mirror.pendingEscape(proof.publicInput.nullifier)!.deadline.toBigInt() - now());
      await h.finalize(proof.publicInput.nullifier);
      await h.reduce();
      expect(balanceOf(alice)).toBe(a + 2n * MINA - MINA / 100n);
    } finally {
      WithdrawalProgram.setProofsEnabled(false);
    }
  }, 1_800_000);
});
