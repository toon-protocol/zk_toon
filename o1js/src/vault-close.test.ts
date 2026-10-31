import { beforeAll, describe, expect, it } from 'vitest';
import { PROOFS_ON } from './proofs-on.js';
import { Field, Mina, PrivateKey, Provable, Signature, verify } from 'o1js';
import * as policy from './policy.js';
import { signClearance } from './clearance.js';
import { commitSecret } from './primitives.js';
import { CLOSE_WINDOW_SLOTS, NullifierSet, REDUCE_BATCH_SIZE, VaultAction, batchReducer } from './vault.js';
import { balanceOf, now, vaultHarness } from './vault-harness.js';
import { VaultMirror } from './vault-mirror.js';
import { WithdrawalKind, WithdrawalProgram } from './withdrawal.js';
import { buildWithdrawal } from './withdrawal-sample.js';

const [SMALL, MEDIUM] = policy.DEPOSIT_SIZES;
const MINA = 1_000_000_000n;

// Proofs off: the contract logic runs, but no circuit is proven. The withdrawal program runs its
// constraints on constants and returns a dummy proof, except where a test compiles it.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
WithdrawalProgram.setProofsEnabled(false);

const { payer, deployer, alice, bob, freshVault } = vaultHarness(Local);

beforeAll(async () => {
  await batchReducer.compile();
});

describe('vault setup', () => {
  it('records the state key and treasury once, with the vault account signature', async () => {
    const h = await freshVault({ setup: false });
    await expect(h.setup({ signer: payer.key })).rejects.toThrow(/not signed by the vault/);
    await expect(h.setup({ signer: h.stateKey })).rejects.toThrow(/not signed by the vault/);
    // A treasury that has no account would fail every payout to it.
    await expect(h.setup({ treasury: PrivateKey.random().toPublicKey() })).rejects.toThrow();
    expect(h.vault.stateKey.get().isEmpty().toBoolean()).toBe(true);
    await h.setup();
    expect(h.vault.stateKey.get().toBase58()).toBe(h.stateKey.toPublicKey().toBase58());
    expect(h.vault.treasury.get().toBase58()).toBe(h.treasury.toBase58());
    await expect(h.setup()).rejects.toThrow(/already set up/);
    // A second state key is refused too.
    await expect(h.setup({ key: PrivateKey.random().toPublicKey() })).rejects.toThrow(/already set up/);
  });

  it('refuses a mutual close before setup', async () => {
    const h = await freshVault({ setup: false });
    const note = await h.deposit();
    await h.reduce();
    const proof = await h.withdrawalProof(note);
    await expect(h.close(proof)).rejects.toThrow(/setup has not run/);
  });
});

describe('vault mutual close', () => {
  let h: Awaited<ReturnType<typeof freshVault>>;
  beforeAll(async () => {
    h = await freshVault();
  });

  it('pays the balance to the destination and the rest to the treasury at the reduce', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const balance = 3_000_000_000n;
    const proof = await h.withdrawalProof(note, { signed: true, balance, destination: alice });
    const [a, t, v] = [balanceOf(alice), balanceOf(h.treasury), balanceOf(h.vault.address)];

    await h.close(proof);
    // The close only dispatches; nothing is paid until the reduce.
    expect([balanceOf(alice), balanceOf(h.treasury), balanceOf(h.vault.address)]).toEqual([a, t, v]);

    await h.reduce();
    expect(balanceOf(alice)).toBe(a + balance);
    expect(balanceOf(h.treasury)).toBe(t + SMALL - balance);
    expect(balanceOf(h.vault.address)).toBe(v - SMALL);

    // The nullifier set now proves the nullifier spent.
    const n = proof.publicInput.nullifier;
    expect(h.vault.nullifierRoot.get().toBigInt()).toBe(h.mirror.nullifiers.root.toBigInt());
    await Provable.runAndCheck(() => {
      const set = Provable.witness(NullifierSet, () => h.mirror.nullifiers.clone());
      set.root.assertEquals(h.vault.nullifierRoot.get());
      set.assertIncluded(n);
    });

    // A second close at that nullifier is refused.
    await expect(h.close(proof)).rejects.toThrow(/nullifier spent/);
  });

  it('pays a genesis note in full to the destination', async () => {
    const note = await h.deposit(MEDIUM);
    await h.reduce();
    const proof = await h.withdrawalProof(note, { destination: bob });
    const [b, t] = [balanceOf(bob), balanceOf(h.treasury)];
    await h.close(proof);
    await h.reduce();
    expect(balanceOf(bob)).toBe(b + MEDIUM);
    expect(balanceOf(h.treasury)).toBe(t);
  });

  it('pays the deposit to the treasury when the balance is zero', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const proof = await h.withdrawalProof(note, { signed: true, balance: 0n, destination: bob });
    const [b, t] = [balanceOf(bob), balanceOf(h.treasury)];
    await h.close(proof);
    await h.reduce();
    expect(balanceOf(bob)).toBe(b);
    expect(balanceOf(h.treasury)).toBe(t + SMALL);
  });

  it('pays two closes of the same state, dispatched before one reduce, exactly once', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const proof = await h.withdrawalProof(note, { destination: bob });
    const [b, v] = [balanceOf(bob), balanceOf(h.vault.address)];
    await h.close(proof);
    await h.close(proof);
    await h.reduce();
    expect(balanceOf(bob)).toBe(b + SMALL);
    expect(balanceOf(h.vault.address)).toBe(v - SMALL);
    expect(h.vault.nullifierRoot.get().toBigInt()).toBe(h.mirror.nullifiers.root.toBigInt());
  });

  it('accepts two closes of different notes in one block and pays both after one reduce', async () => {
    const one = await h.deposit(SMALL);
    const two = await h.deposit(SMALL);
    await h.reduce();
    const p1 = await h.withdrawalProof(one, { destination: alice });
    const p2 = await h.withdrawalProof(two, { destination: bob });
    // Two payers build both against the same chain state before either is sent.
    const slot = Mina.getNetworkState().globalSlotSinceGenesis.toBigint();
    const tx1 = await h.closeTx(p1, h.clearance(p1.publicInput), payer);
    const tx2 = await h.closeTx(p2, h.clearance(p2.publicInput), deployer);
    const [a, b] = [balanceOf(alice), balanceOf(bob)];
    await h.send(tx1, [], payer);
    await h.send(tx2, [], deployer);
    expect(Mina.getNetworkState().globalSlotSinceGenesis.toBigint()).toBe(slot);
    h.mirror.dispatched(VaultAction.mutualClose(p1.publicInput));
    h.mirror.dispatched(VaultAction.mutualClose(p2.publicInput));
    await h.reduce();
    expect(balanceOf(alice)).toBe(a + SMALL);
    expect(balanceOf(bob)).toBe(b + SMALL);
  });

  it('pays a full batch of closes in one reduce', async () => {
    const notes = [];
    for (let i = 0; i < REDUCE_BATCH_SIZE; i++) notes.push(await h.deposit(SMALL));
    await h.reduce();
    const dests = [alice, bob];
    const proofs = [];
    for (const [i, note] of notes.entries()) {
      proofs.push(await h.withdrawalProof(note, { signed: true, balance: BigInt(i + 1) * MINA, destination: dests[i % 2] }));
    }
    const before = dests.map(balanceOf);
    for (const p of proofs) await h.close(p);
    await h.reduce();
    const paid = [0n, 0n];
    proofs.forEach((p, i) => (paid[i % 2] += p.publicInput.amount.toBigInt()));
    dests.forEach((d, i) => expect(balanceOf(d)).toBe(before[i] + paid[i]));
  });

  it('refuses a missing clearance, or one by another key, over another nullifier or destination', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const proof = await h.withdrawalProof(note);
    const pub = proof.publicInput;
    const refused = [
      Signature.create(PrivateKey.random(), [Field(0)]),
      h.clearance(pub, { key: PrivateKey.random() }),
      h.clearance(pub, { nullifier: pub.nullifier.add(1) }),
      h.clearance(pub, { destination: bob }),
    ];
    for (const c of refused) await expect(h.close(proof, c)).rejects.toThrow(/bad clearance/);
    // A proof bound to another destination is refused under the clearance the zk edge gave.
    const elsewhere = await h.withdrawalProof(note, { destination: bob });
    await expect(h.close(elsewhere, h.clearance(pub))).rejects.toThrow(/bad clearance/);
  });

  it('refuses an ownership proof', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    const proof = await h.withdrawalProof(note, { kind: WithdrawalKind.ownership });
    await expect(h.close(proof)).rejects.toThrow(/not a mutual close/);
  });

  it('refuses a root not in the ring and another state key', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    // A note the vault never reduced: its tree's root is not the vault's.
    const stale = new VaultMirror();
    stale.tree.append({ commitment: commitSecret(Field(note.secret)), size: Field(note.size), depositTime: Field(note.depositTime) });
    const { pub, priv } = buildWithdrawal(stale.tree, {
      kind: WithdrawalKind.mutualClose, secret: note.secret, index: 0n, size: note.size, depositTime: note.depositTime,
      requestTime: now(), signed: false, balance: 0n, blinding: 1n, stateKey: h.stateKey, destination: alice,
    });
    const { proof } = await WithdrawalProgram.mutualClose(pub, priv);
    await expect(h.close(proof)).rejects.toThrow(/root not in the ring/);

    // A state signed under another key: the proof names that key as `vault`.
    const other = PrivateKey.random();
    const foreign = await h.withdrawalProof(note, { signed: true, balance: 1n, key: other });
    await expect(h.close(foreign, signClearance(other, {
      stateKey: other.toPublicKey(), nullifier: foreign.publicInput.nullifier, destination: alice,
    }))).rejects.toThrow(/not the state key/);
  });

  it('refuses an expired note', async () => {
    const note = await h.deposit(SMALL);
    await h.reduce();
    // No proof can be made for a requestTime at or past the note's expiry.
    await expect(h.withdrawalProof(note, { requestTime: policy.expiryOf(note.depositTime) })).rejects.toThrow();
  });
});

// Its own vault, since LocalBlockchain records the actions of a transaction its preconditions reject.
describe('vault mutual close timing', () => {
  it('refuses a slot outside [requestTime, requestTime + 7 slots]', async () => {
    // Far enough past genesis that the window's lower edge is a real slot.
    Local.incrementGlobalSlot(100);
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    const t = now();
    for (const requestTime of [t + 1n, t - CLOSE_WINDOW_SLOTS - 1n]) {
      const proof = await h.withdrawalProof(note, { requestTime });
      await expect(h.send(await h.closeTx(proof, h.clearance(proof.publicInput)))).rejects.toThrow(/Valid_while_precondition_unsatisfied/);
    }
    // At the window's edges, accepted.
    for (const requestTime of [t, t - CLOSE_WINDOW_SLOTS]) {
      const proof = await h.withdrawalProof(note, { requestTime });
      await h.send(await h.closeTx(proof, h.clearance(proof.publicInput)));
    }
  });
});

// Its own vault, since LocalBlockchain records the actions of a transaction its preconditions reject.
describe('vault mutual close destination', () => {
  it('refuses a destination that has no account, which would fail the reduce', async () => {
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    const proof = await h.withdrawalProof(note, { destination: PrivateKey.random().toPublicKey() });
    await expect(h.send(await h.closeTx(proof, h.clearance(proof.publicInput)))).rejects.toThrow();
  });
});

describe('vault mutual close with a real withdrawal proof', () => {
  it(PROOFS_ON.close, async () => {
    const { verificationKey } = await WithdrawalProgram.compile({ proofsEnabled: true });
    WithdrawalProgram.setProofsEnabled(true);
    try {
      const h = await freshVault();
      const note = await h.deposit(SMALL);
      await h.reduce();
      const proof = await h.withdrawalProof(note, { signed: true, balance: 1_000_000_000n, destination: alice });
      expect(await verify(proof, verificationKey)).toBe(true);
      const a = balanceOf(alice);
      await h.close(proof);
      await h.reduce();
      expect(balanceOf(alice)).toBe(a + 1_000_000_000n);
    } finally {
      WithdrawalProgram.setProofsEnabled(false);
    }
  }, 1_800_000);
});
