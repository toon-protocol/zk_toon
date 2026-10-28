import { beforeAll, describe, expect, it } from 'vitest';
import { AccountUpdate, Field, Mina, PrivateKey, UInt64, Unconstrained } from 'o1js';
import * as policy from './policy.js';
import { commitSecret, leaf } from './primitives.js';
import { DepositLike, NoteTree, emptyNoteRoot, reduceWitnesses } from './note-tree.js';
import { NullifierSet, REDUCE_BATCH_SIZE, ROOT_RING_LENGTH, SLOT_MS, Vault, batchReducer } from './vault.js';

const [SMALL, MEDIUM] = policy.DEPOSIT_SIZES;

// Proofs off: the contract logic runs, but no circuit is proven.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);

describe('vault deposit path', () => {
  const [payer, deployer] = Local.testAccounts;
  const zkappKey = PrivateKey.random();
  const vault = new Vault(zkappKey.toPublicKey());
  let deployTime: bigint;
  const tree = new NoteTree();
  const queue: DepositLike[] = [];
  let secret = 1n;
  let lastDeposit: DepositLike;

  // The network's timestamp is that of the current slot's start.
  const now = () => {
    const { genesisTimestamp, slotTime } = Mina.getNetworkConstants();
    return genesisTimestamp.toBigInt() + Mina.getNetworkState().globalSlotSinceGenesis.toBigint() * slotTime.toBigInt();
  };
  const balance = () => Mina.getBalance(vault.address).toBigInt();
  const send = async (tx: Awaited<ReturnType<typeof Mina.transaction>>) => {
    await tx.prove();
    await tx.sign([payer.key]).send();
  };

  async function deposit(size: bigint, depositTime = now()) {
    const c = commitSecret(Field(secret++));
    await send(
      await Mina.transaction(payer, async () => {
        await vault.deposit(c, UInt64.from(size), UInt64.from(depositTime));
      })
    );
    lastDeposit = { commitment: c, size: Field(size), depositTime: Field(depositTime) };
    queue.push(lastDeposit);
  }

  /** One reduce transaction per prepared batch, like a keeper would run. */
  async function reduce() {
    for (const { batch, proof } of await batchReducer.prepareBatches()) {
      const deposits = queue.splice(0, REDUCE_BATCH_SIZE);
      const witnesses = reduceWitnesses(tree, deposits, REDUCE_BATCH_SIZE);
      await send(
        await Mina.transaction(payer, async () => {
          // Deposits only: the nullifier set stays empty.
          await vault.reduce(batch, proof, Unconstrained.from(witnesses), new NullifierSet());
        })
      );
    }
  }

  const ring = () => vault.rootRing.get().roots.map((r) => r.toBigInt());

  beforeAll(async () => {
    batchReducer.setContractInstance(vault);
    await batchReducer.compile();
    const tx = await Mina.transaction(deployer, async () => {
      AccountUpdate.fundNewAccount(deployer);
      await vault.deploy();
    });
    await tx.prove();
    await tx.sign([deployer.key, zkappKey]).send();
    deployTime = now();
  });

  it('records creation time, sizes, note lifetime and challenge window in state', () => {
    expect(vault.creationTime.get().toBigInt()).toBe(deployTime);
    const sizes = vault.depositSizes.get();
    expect([sizes.a, sizes.b, sizes.c].map((s) => s.toBigInt())).toEqual([...policy.DEPOSIT_SIZES]);
    expect(vault.noteLifetime.get().toBigInt()).toBe(policy.NOTE_LIFETIME_MS);
    expect(vault.challengeWindow.get().toBigInt()).toBe(policy.CHALLENGE_WINDOW_MS);
    expect(vault.noteRoot.get().toBigInt()).toBe(emptyNoteRoot().toBigInt());
  });

  it('keeps a deposit out of the tree until reduce, then holds the shared leaf at its index', async () => {
    const before = balance();
    await deposit(SMALL);
    expect(balance()).toBe(before + SMALL);
    expect(vault.noteRoot.get().toBigInt()).toBe(emptyNoteRoot().toBigInt());
    expect(vault.nextLeafIndex.get().toBigInt()).toBe(0n);

    await reduce();
    const leafAtZero = tree.leafAt(0n);
    const expected = leaf(Field(0), lastDeposit.commitment, Field(SMALL), lastDeposit.depositTime, Field(policy.expiryOf(lastDeposit.depositTime.toBigInt())));
    expect(leafAtZero.toBigInt()).toBe(expected.toBigInt());
    expect(vault.noteRoot.get().toBigInt()).toBe(tree.root.toBigInt());
    expect(vault.nextLeafIndex.get().toBigInt()).toBe(1n);
    expect(ring()).toContain(tree.root.toBigInt());
  });

  it('refuses amounts just below and just above a configured size', async () => {
    const before = balance();
    for (const size of [SMALL - 1n, SMALL + 1n, MEDIUM - 1n, MEDIUM + 1n, 0n]) {
      await expect(deposit(size)).rejects.toThrow();
    }
    expect(balance()).toBe(before);
  });

  it('turns two deposits of one block into consecutive notes with a single reduce', async () => {
    const first = vault.nextLeafIndex.get().toBigInt();
    await deposit(SMALL);
    await deposit(MEDIUM);
    expect(vault.nextLeafIndex.get().toBigInt()).toBe(first);
    await reduce();
    expect(vault.nextLeafIndex.get().toBigInt()).toBe(first + 2n);
    expect(tree.nextIndex).toBe(first + 2n);
    expect(vault.noteRoot.get().toBigInt()).toBe(tree.root.toBigInt());
  });

  it('remembers the latest 8 roots: after 9 reduces the first is gone', async () => {
    const roots: bigint[] = [];
    for (let i = 0; i < ROOT_RING_LENGTH + 1; i++) {
      await deposit(SMALL);
      await reduce();
      roots.push(vault.noteRoot.get().toBigInt());
    }
    const held = ring();
    expect(held).not.toContain(roots[0]);
    for (const r of roots.slice(1)) expect(held).toContain(r);
    expect(held.filter((r) => r !== 0n)).toHaveLength(ROOT_RING_LENGTH);
    const ringState = vault.rootRing.get();
    expect(ringState.contains(Field(roots[0])).toBoolean()).toBe(false);
    for (const r of roots.slice(1)) expect(ringState.contains(Field(r)).toBoolean()).toBe(true);
    expect(ringState.contains(Field(0)).toBoolean()).toBe(false);
  });

  // Last: LocalBlockchain records the actions of a rejected transaction, so these leave actions behind
  // that a real chain would not hold; the earlier tests need a clean action list.
  it('refuses a deposit time that does not match the block timestamp within one slot', async () => {
    const before = balance();
    await expect(deposit(SMALL, now() + 2n * SLOT_MS)).rejects.toThrow();
    await expect(deposit(SMALL, now() - 2n * SLOT_MS)).rejects.toThrow();
    expect(balance()).toBe(before);
    await deposit(SMALL, now() - SLOT_MS / 2n);
    expect(balance()).toBe(before + SMALL);
  });
});
