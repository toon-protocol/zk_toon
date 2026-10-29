import { beforeAll, describe, expect, it } from 'vitest';
import { AccountUpdate, Field, Mina, PrivateKey, PublicKey, Scalar, Signature, UInt64, Unconstrained } from 'o1js';
import { signClearance } from './clearance.js';
import * as policy from './policy.js';
import { commitSecret } from './primitives.js';
import { DepositLike, NoteTree, reduceWitnesses } from './note-tree.js';
import {
  CLOSE_WINDOW_MS, NullifierMap, REDUCE_BATCH_SIZE, Vault, batchReducer, setupFields,
} from './vault.js';
import { KIND_MUTUAL_CLOSE, KIND_OWNERSHIP, WithdrawalProgram, WithdrawalProof, type WithdrawalPublic } from './withdrawal.js';
import { buildWithdrawal, defaultWithdrawal, type WithdrawalSample } from './withdrawal-sample.js';

const [SMALL] = policy.DEPOSIT_SIZES;
const MINA = 1_000_000_000n;

// Proofs off: the contract logic runs, but no circuit is proven.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);

describe('vault mutual close', () => {
  const [payer, deployer, treasuryAcct, destA, destB, destC] = Local.testAccounts;
  const zkappKey = PrivateKey.random();
  const vault = new Vault(zkappKey.toPublicKey());
  const stateKey = PrivateKey.fromBigInt(1n); // the sample's vault key
  const tree = new NoteTree();
  const nullifiers = new NullifierMap();
  /** What the keeper mirrors for the next reduce: a deposit, or a close (undefined deposit). */
  const queue: { deposit?: DepositLike; nullifier?: Field }[] = [];
  let nextSecret = 1000n;
  /** A reduced note kept for the tests that must come last. */
  let spare: Note;

  const now = () => {
    const { genesisTimestamp, slotTime } = Mina.getNetworkConstants();
    return genesisTimestamp.toBigInt() + Mina.getNetworkState().globalSlotSinceGenesis.toBigint() * slotTime.toBigInt();
  };
  const bal = (a: PublicKey) => Mina.getBalance(a).toBigInt();
  const send = async (tx: Awaited<ReturnType<typeof Mina.transaction>>) => {
    await tx.prove();
    await tx.sign([payer.key]).send();
  };

  interface Note { secret: bigint; index: bigint; size: bigint; depositTime: bigint }
  async function deposit(size = SMALL): Promise<Note> {
    const secret = nextSecret++;
    const depositTime = now();
    const c = commitSecret(Field(secret));
    await send(
      await Mina.transaction(payer, async () => {
        await vault.deposit(c, UInt64.from(size), UInt64.from(depositTime));
      })
    );
    queue.push({ deposit: { commitment: c, size: Field(size), depositTime: Field(depositTime) } });
    return { secret, index: BigInt(tree.nextIndex) + BigInt(queue.filter((q) => q.deposit).length - 1), size, depositTime };
  }

  async function reduce() {
    for (const { batch, proof } of await batchReducer.prepareBatches()) {
      const entries = queue.splice(0, REDUCE_BATCH_SIZE);
      const witnesses = reduceWitnesses(tree, entries.map((e) => e.deposit), REDUCE_BATCH_SIZE);
      await send(
        await Mina.transaction(payer, async () => {
          await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers);
        })
      );
      // The keeper's mirror of the set takes the closes' nullifiers, in order.
      for (const e of entries) if (e.nullifier) nullifiers.set(e.nullifier, 1n);
    }
  }

  /** A deposited-and-reduced note, as a deposit followed by a reduce. */
  async function note(size = SMALL) {
    const n = await deposit(size);
    await reduce();
    return n;
  }

  /** The withdrawal inputs for a note; `balance` makes it a signed state, otherwise it is the genesis state. */
  function withdrawal(n: Note, o: { kind?: number; dest?: PublicKey; balance?: bigint; requestTime?: bigint; vaultSecret?: bigint } = {}) {
    const dest = o.dest ?? destA.key.toPublicKey();
    const sample = buildWithdrawal(
      {
        ...defaultWithdrawal(o.kind ?? KIND_MUTUAL_CLOSE),
        secret: n.secret, size: n.size, depositTime: n.depositTime, requestTime: o.requestTime ?? now(),
        signed: o.balance !== undefined, balance: o.balance ?? 0n, blinding: 9_000_111n,
        vaultSecret: o.vaultSecret ?? 1n, destinationSecret: PrivateKey.fromBase58(destKeyOf(dest)).toBigInt(),
      },
      { tree, index: n.index }
    );
    return sample;
  }
  const keys = new Map<string, string>();
  const destKeyOf = (pub: PublicKey) => keys.get(pub.toBase58())!;

  const clearanceFor = (s: WithdrawalSample, over: { nullifier?: Field; destination?: PublicKey; key?: PrivateKey } = {}) =>
    signClearance(over.key ?? stateKey, {
      stateKey: stateKey.toPublicKey(),
      nullifier: over.nullifier ?? s.pub.nullifier,
      destination: over.destination ?? s.pub.destination,
    });

  async function close(s: WithdrawalSample, clearance: Signature = clearanceFor(s), pub?: WithdrawalPublic) {
    const proof = await WithdrawalProof.dummy(pub ?? s.pub, undefined, 0);
    await send(
      await Mina.transaction(payer, async () => {
        await vault.mutualClose(proof, clearance, nullifiers);
      })
    );
    queue.push({ nullifier: s.pub.nullifier });
  }

  beforeAll(async () => {
    for (const a of [destA, destB, destC]) keys.set(a.key.toPublicKey().toBase58(), a.key.toBase58());
    batchReducer.setContractInstance(vault);
    await batchReducer.compile();
    const tx = await Mina.transaction(deployer, async () => {
      AccountUpdate.fundNewAccount(deployer);
      await vault.deploy();
    });
    await tx.prove();
    await tx.sign([deployer.key, zkappKey]).send();
  });

  it('refuses a mutual close before setup has run', async () => {
    const n = await note();
    await expect(close(withdrawal(n))).rejects.toThrow(/setup has not run/);
  });

  it('refuses setup without the vault account’s signature, and runs it once', async () => {
    const treasury = treasuryAcct.key.toPublicKey();
    const setup = async (signer: PrivateKey) => {
      const sig = Signature.create(signer, setupFields(vault.address, stateKey.toPublicKey(), treasury));
      await send(
        await Mina.transaction(payer, async () => {
          await vault.setup(stateKey.toPublicKey(), treasury, sig);
        })
      );
    };
    // A treasury that has no account would fail every payout to it.
    const absent = PrivateKey.random().toPublicKey();
    const absentSig = Signature.create(zkappKey, setupFields(vault.address, stateKey.toPublicKey(), absent));
    await expect(
      send(
        await Mina.transaction(payer, async () => {
          await vault.setup(stateKey.toPublicKey(), absent, absentSig);
        })
      )
    ).rejects.toThrow();
    expect(vault.stateKey.get().x.toBigInt()).toBe(0n);
    await expect(setup(payer.key)).rejects.toThrow(/not signed by the vault/);
    await expect(setup(stateKey)).rejects.toThrow(/not signed by the vault/);
    expect(vault.stateKey.get().x.toBigInt()).toBe(0n);
    await setup(zkappKey);
    expect(vault.stateKey.get().equals(stateKey.toPublicKey()).toBoolean()).toBe(true);
    expect(vault.treasury.get().equals(treasury).toBoolean()).toBe(true);
    await expect(setup(zkappKey)).rejects.toThrow(/already set up/);
    // A second state key is refused too.
    const other = PrivateKey.fromBigInt(5n).toPublicKey();
    const sig = Signature.create(zkappKey, setupFields(vault.address, other, treasury));
    await expect(
      Mina.transaction(payer, async () => {
        await vault.setup(other, treasury, sig);
      })
    ).rejects.toThrow(/already set up/);
  });

  it('pays amount to the destination and size − amount to the treasury, at the reduce', async () => {
    const n = await note();
    const balance = 4n * MINA;
    const s = withdrawal(n, { balance, dest: destA.key.toPublicKey() });
    expect(s.pub.amount.toBigInt()).toBe(balance);
    const [vaultBefore, destBefore, treasuryBefore] = [bal(vault.address), bal(destA.key.toPublicKey()), bal(treasuryAcct.key.toPublicKey())];

    await close(s);
    // The close itself pays nothing.
    expect(bal(vault.address)).toBe(vaultBefore);
    expect(bal(destA.key.toPublicKey())).toBe(destBefore);
    expect(vault.nullifierRoot.get().toBigInt()).toBe(nullifiers.root.toBigInt());

    await reduce();
    expect(bal(destA.key.toPublicKey())).toBe(destBefore + balance);
    expect(bal(treasuryAcct.key.toPublicKey())).toBe(treasuryBefore + n.size - balance);
    expect(bal(vault.address)).toBe(vaultBefore - n.size);

    // The nullifier is in the set, and the on-chain root is the set's.
    expect(vault.nullifierRoot.get().toBigInt()).toBe(nullifiers.root.toBigInt());
    expect(nullifiers.isIncluded(s.pub.nullifier).toBoolean()).toBe(true);
    expect(nullifiers.get(s.pub.nullifier).toBigInt()).toBe(1n);

    // A second close at that nullifier is refused.
    await expect(close(s)).rejects.toThrow(/nullifier spent/);
  });

  it('pays a full balance to the destination and nothing to the treasury', async () => {
    const n = await note();
    const s = withdrawal(n, { dest: destB.key.toPublicKey() });
    const [destBefore, treasuryBefore] = [bal(destB.key.toPublicKey()), bal(treasuryAcct.key.toPublicKey())];
    await close(s);
    await reduce();
    expect(bal(destB.key.toPublicKey())).toBe(destBefore + n.size);
    expect(bal(treasuryAcct.key.toPublicKey())).toBe(treasuryBefore);
  });

  it('pays a zero balance wholly to the treasury', async () => {
    const n = await note();
    const s = withdrawal(n, { balance: 0n, dest: destC.key.toPublicKey() });
    const [destBefore, treasuryBefore] = [bal(destC.key.toPublicKey()), bal(treasuryAcct.key.toPublicKey())];
    await close(s);
    await reduce();
    expect(bal(destC.key.toPublicKey())).toBe(destBefore);
    expect(bal(treasuryAcct.key.toPublicKey())).toBe(treasuryBefore + n.size);
  });

  it('pays exactly once when one state is closed twice before a reduce, and the reduce does not fail', async () => {
    const n = await note();
    const s = withdrawal(n, { balance: 3n * MINA, dest: destA.key.toPublicKey() });
    const [vaultBefore, destBefore] = [bal(vault.address), bal(destA.key.toPublicKey())];
    await close(s);
    await close(s); // the set does not hold the nullifier yet
    await reduce();
    expect(bal(destA.key.toPublicKey())).toBe(destBefore + 3n * MINA);
    expect(bal(vault.address)).toBe(vaultBefore - n.size);
    expect(nullifiers.isIncluded(s.pub.nullifier).toBoolean()).toBe(true);
  });

  it('accepts two closes of different notes in one block and pays both after one reduce', async () => {
    const a = await note();
    const b = await note();
    const sa = withdrawal(a, { balance: 2n * MINA, dest: destA.key.toPublicKey() });
    const sb = withdrawal(b, { balance: 5n * MINA, dest: destB.key.toPublicKey() });
    const [da, db, tr] = [bal(destA.key.toPublicKey()), bal(destB.key.toPublicKey()), bal(treasuryAcct.key.toPublicKey())];
    await close(sa);
    await close(sb);
    await reduce();
    expect(bal(destA.key.toPublicKey())).toBe(da + 2n * MINA);
    expect(bal(destB.key.toPublicKey())).toBe(db + 5n * MINA);
    expect(bal(treasuryAcct.key.toPublicKey())).toBe(tr + a.size - 2n * MINA + b.size - 5n * MINA);
  });

  it('pays a full batch of closes in one reduce', async () => {
    const notes: Note[] = [];
    for (let i = 0; i < REDUCE_BATCH_SIZE; i++) notes.push(await deposit());
    await reduce();
    const dests = [destA, destB, destC];
    const samples = notes.map((n, i) => withdrawal(n, { balance: BigInt(i + 1) * MINA, dest: dests[i % 3].key.toPublicKey() }));
    const before = dests.map((d) => bal(d.key.toPublicKey()));
    for (const s of samples) await close(s);
    await reduce();
    const paid = [0n, 0n, 0n];
    samples.forEach((s, i) => (paid[i % 3] += s.pub.amount.toBigInt()));
    dests.forEach((d, i) => expect(bal(d.key.toPublicKey())).toBe(before[i] + paid[i]));
  });

  it('refuses a missing clearance, and one by another key, over another nullifier or over another destination', async () => {
    const n = await note();
    const s = withdrawal(n);
    const wrong = [
      Signature.fromObject({ r: Field(0), s: Scalar.from(0n) }),
      clearanceFor(s, { key: PrivateKey.fromBigInt(2n) }),
      clearanceFor(s, { nullifier: s.pub.nullifier.add(1) }),
      clearanceFor(s, { destination: destB.key.toPublicKey() }),
    ];
    for (const c of wrong) await expect(close(s, c)).rejects.toThrow(/bad clearance/);
    await close(s); // the right one is accepted
  });

  it('refuses an ownership proof', async () => {
    const n = await note();
    const s = withdrawal(n, { kind: KIND_OWNERSHIP });
    await expect(close(s)).rejects.toThrow(/not a mutual close/);
  });

  it('refuses a root outside the ring, and a vault input other than the state key', async () => {
    const n = await note();
    const s = withdrawal(n);
    const bad = { ...s.pub, root: s.pub.root.add(1) } as WithdrawalPublic;
    await expect(close(s, clearanceFor(s), bad)).rejects.toThrow(/root not in the ring/);
    const other = withdrawal(n, { vaultSecret: 2n });
    await expect(close(other, clearanceFor(other))).rejects.toThrow(/not the state key/);
  });

  it('runs a mutual close with a real withdrawal proof', async () => {
    const n = await note();
    const s = withdrawal(n, { balance: 6n * MINA, dest: destB.key.toPublicKey() });
    await WithdrawalProgram.compile();
    const { proof } = await WithdrawalProgram.mutualClose(s.pub, s.priv);
    const destBefore = bal(destB.key.toPublicKey());
    await send(
      await Mina.transaction(payer, async () => {
        await vault.mutualClose(proof, clearanceFor(s), nullifiers);
      })
    );
    queue.push({ nullifier: s.pub.nullifier });
    await reduce();
    expect(bal(destB.key.toPublicKey())).toBe(destBefore + 6n * MINA);
  }, 1_800_000);

  // Last: LocalBlockchain records the actions of a transaction that fails at send, which a real chain would
  // not hold; the earlier tests need a clean action list.
  it('refuses a destination that has no account, which would fail the reduce', async () => {
    spare = await note();
    const n = await note();
    const fresh = PrivateKey.random();
    keys.set(fresh.toPublicKey().toBase58(), fresh.toBase58());
    await expect(close(withdrawal(n, { dest: fresh.toPublicKey() }))).rejects.toThrow();
  });

  it('refuses a block time outside [requestTime, requestTime + 10 min]', async () => {
    const n = spare;
    const late = withdrawal(n, { requestTime: now() - CLOSE_WINDOW_MS - 2n * 90_000n });
    await expect(close(late)).rejects.toThrow();
    const early = withdrawal(n, { requestTime: now() + 3_600_000n });
    await expect(close(early)).rejects.toThrow();
    const edge = withdrawal(n, { requestTime: now() - CLOSE_WINDOW_MS });
    await close(edge);
  });
});
