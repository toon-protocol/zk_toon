// The check a client runs before trusting a vault (#75, ADR 0008). A forged vault here is what a deployer can
// really make (`vault-forge.ts`).
import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { AccountUpdate, Bool, Experimental, Field, Mina, PrivateKey, PublicKey, UInt64, Unconstrained } from 'o1js';
import { NoteTree } from './note-tree.js';
import { commitSecret } from './primitives.js';
import * as policy from './policy.js';
import { RequestProgram } from './request.js';
import { signClearance } from './clearance.js';
import { LOCKED, LOOSENED, dispatch, dispatchTogether, forged as forgedBy, forgedClose as forgedCloseTo, phantomDeposit, writeReducedDeposit } from './vault-forge.js';
import { ActionKind, CLOSE_WINDOW_SLOTS, DepositSizes, NullifierSet, PendingEscape, RootRing, Vault, VaultAction, batchReducer } from './vault.js';
import { checkVault, chainReader, judgeVault, type VaultReader, type VaultSnapshot, type VaultVerdict } from './vault-check.js';
import { balanceOf, now, vaultHarness } from './vault-harness.js';
import { reduceMirror, vaultView } from './vault-view.js';
import { WithdrawalKind, WithdrawalProgram } from './withdrawal.js';
import { buildWithdrawal } from './withdrawal-sample.js';

const [SMALL] = policy.DEPOSIT_SIZES;
const MINA = 1_000_000_000n;
const [, , TOP_TIER] = policy.TIERS;

const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
WithdrawalProgram.setProofsEnabled(false);
RequestProgram.setProofsEnabled(false);

const { payer, deployer, alice, bob, advance, freshVault, treasuryAccount } = vaultHarness(Local);
const reader = chainReader({ localChain: true });

/** With proofs off every vault carries o1js's dummy key: this is its hash, in place of the published one. */
let codeHash: string;
beforeAll(async () => {
  await batchReducer.compile();
  const h = await freshVault();
  codeHash = Mina.getAccount(h.vault.address).zkapp!.verificationKey!.hash.toString();
});

const check = (address: PublicKey, o: { reader?: VaultReader; codeHash?: string } = {}) =>
  checkVault(address, { codeHash: o.codeHash ?? codeHash, reader: o.reader ?? reader });
const failed = (v: VaultVerdict) => (v.pass ? [] : v.refusals.map((r) => r.check));
const expectPass = (v: VaultVerdict) => expect(v.pass ? 'pass' : v.refusals).toBe('pass');

const forged = (o: Parameters<typeof forgedBy>[1] = {}) => forgedBy({ deployer, treasury: treasuryAccount }, o);
const forgedClose = () => forgedCloseTo(alice);
const forgedEscape = () => new PendingEscape({
  nullifier: Field(5), nextNullifier: Field(6), amount: UInt64.from(SMALL), conceded: UInt64.zero, size: UInt64.from(SMALL), destination: alice,
  deadline: UInt64.from(now() + 2000n),
});
const emptyStack = Experimental.BatchReducer.initialActionStack;
/** Runs every reduce a vault outside the harness has pending. */
const reduceAll = async (vault: Vault) => {
  batchReducer.setContractInstance(vault);
  const { mirror, pending } = await reduceMirror(vault);
  expect(pending).toBeGreaterThan(0);
  for (const { batch, proof } of await batchReducer.prepareBatches()) {
    const { witnesses, nullifiers, escapes } = mirror.nextReduce(now());
    const tx = await Mina.transaction(payer, async () => {
      await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(now()));
    });
    await tx.prove();
    await tx.sign([payer.key]).send();
  }
};

describe('a vault that is what it says', () => {
  it('passes fresh, with nothing to replay', async () => {
    expect(await check((await freshVault()).vault.address)).toEqual({ pass: true, dispatched: 0, reduced: 0 });
  });

  it('passes after deposits, closes, escapes, a raise, a defeat, a finalize and a sweep, and at every step between', async () => {
    const h = await freshVault();
    const pass = async () => expectPass(await check(h.vault.address));
    const reduce = async () => { await pass(); await h.reduce(); await pass(); };

    const notes = [await h.deposit(SMALL), await h.deposit(SMALL), await h.deposit(SMALL), await h.deposit(SMALL)];
    await reduce();

    await h.close(await h.withdrawalProof(notes[0]!, { signed: true, balance: 3n * MINA }));
    const raised = await h.withdrawalProof(notes[1]!, { kind: WithdrawalKind.escape, signed: true, balance: 3n * MINA });
    const defeated = await h.withdrawalProof(notes[2]!, { kind: WithdrawalKind.escape, signed: true, balance: 2n * MINA });
    await h.escape(raised);
    await h.escape(defeated);
    await reduce();

    await h.raise(raised.publicInput.nullifier, await h.requestProof(notes[1]!, { tier: TOP_TIER, balance: 3n * MINA }), MINA / 2n);
    await h.defeat(defeated.publicInput.nullifier, await h.requestProof(notes[2]!, { step: 2, tier: TOP_TIER }));
    await reduce();

    advance(h.mirror.pendingEscape(raised.publicInput.nullifier)!.deadline.toBigInt() - now());
    await h.finalize(raised.publicInput.nullifier);
    await reduce();

    advance(policy.NOTE_LIFETIME_SLOTS + CLOSE_WINDOW_SLOTS);
    await h.sweep();
    await reduce();
    const v = await check(h.vault.address);
    expect(v).toEqual({ pass: true, dispatched: 11, reduced: 11 });
    // The three notes that aren't the defeated one have paid out, and the sweep took that one's deposit too.
    expect(balanceOf(h.vault.address)).toBe(0n);
  });

  it('passes between the batches of a reduce, with its action stack on the account', async () => {
    const h = await freshVault();
    for (let i = 0; i < 5; i++) await h.deposit(SMALL);
    batchReducer.setContractInstance(h.vault);
    const [first] = await batchReducer.prepareBatches();
    const { witnesses, nullifiers, escapes } = h.mirror.nextReduce(now());
    await h.send(await Mina.transaction(payer, async () => {
      await h.vault.reduce(first!.batch, first!.proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(now()));
    }));
    expect(h.vault.actionStack.get().equals(emptyStack).toBoolean()).toBe(false);
    expect(await check(h.vault.address)).toEqual({ pass: true, dispatched: 5, reduced: 4 });
  });

  it('refuses a stale escape only while it stands: a defeat clears it, and for good', async () => {
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    await h.close(await h.withdrawalProof(note, { signed: true, step: 3, balance: MINA }));
    const stale = await h.withdrawalProof(note, { kind: WithdrawalKind.escape, signed: true, step: 1, balance: 3n * MINA });
    await h.escape(stale);
    await h.reduce();
    expect(failed(await check(h.vault.address))).toEqual(['claims']);
    await h.defeat(stale.publicInput.nullifier, await h.requestProof(note, { step: 2, tier: TOP_TIER }));
    await h.reduce();
    expectPass(await check(h.vault.address));
  });

  it('passes with more in it than its deposits, since anyone may credit a vault', async () => {
    const h = await freshVault();
    await h.send(await Mina.transaction(bob, async () => {
      AccountUpdate.createSigned(bob).send({ to: h.vault.address, amount: UInt64.from(MINA) });
    }), [bob.key]);
    expectPass(await check(h.vault.address));
  });
});

describe('a vault the code hash cannot tell apart', () => {
  it('is refused under another code hash', async () => {
    const { vault } = await freshVault();
    expect(failed(await check(vault.address, { codeHash: '12345' }))).toEqual(['codeHash']);
  });

  it('is what the forger helper builds, with nothing changed: a pass', async () => {
    expectPass(await check((await forged()).address));
  });

  it.each(Object.keys(LOCKED()) as (keyof ReturnType<typeof LOCKED>)[])('is refused with %s changed', async (name) => {
    const vault = await forged({ permissions: { [name]: LOOSENED[name]() } });
    expect(failed(await check(vault.address))).toEqual([`permissions.${name}`]);
  });

  it('is refused with a vesting schedule', async () => {
    expect(failed(await check((await forged({ timed: true })).address))).toEqual(['timing']);
  });

  const sizes = (over: Partial<{ a: UInt64; b: UInt64; c: UInt64 }>) => new DepositSizes({ ...DepositSizes.fromPolicy(), ...over });
  it.each<[string, (v: Vault) => void]>([
    ['depositSizes.a', (v) => v.depositSizes.set(sizes({ a: UInt64.from(1) }))],
    ['depositSizes.b', (v) => v.depositSizes.set(sizes({ b: UInt64.from(1) }))],
    ['depositSizes.c', (v) => v.depositSizes.set(sizes({ c: UInt64.from(1) }))],
    ['noteLifetime', (v) => v.noteLifetime.set(UInt64.from(1))],
    ['challengeWindow', (v) => v.challengeWindow.set(UInt64.from(1))],
    ['creationTime', (v) => v.creationTime.set(UInt64.from(now() + 100n))],
  ])('is refused with %s changed', async (name, write) => {
    expect(failed(await check((await forged({ write })).address))).toEqual([name]);
  });

  it('is refused before setup', async () => {
    const { vault } = await freshVault({ setup: false });
    expect(failed(await check(vault.address))).toEqual(['setup', 'setup']);
  });

  it('is refused when its treasury has no account', async () => {
    const vault = await forged();
    const missing: VaultReader = { ...reader, account: async (a) => (a.equals(treasuryAccount).toBoolean() ? undefined : reader.account(a)) };
    expect(failed(await check(vault.address, { reader: missing }))).toEqual(['setup']);
  });
});

describe('a vault whose state its actions do not explain', () => {
  it.each<[string, (v: Vault) => void]>([
    ['noteRoot', (v) => v.noteRoot.set(Field(123))],
    ['nextLeafIndex', (v) => v.nextLeafIndex.set(Field(1))],
    ['nullifierRoot', (v) => v.nullifierRoot.set(Field(123))],
    ['pendingEscapesRoot', (v) => v.pendingEscapesRoot.set(Field(123))],
    ['claimedTotal', (v) => v.claimedTotal.set(UInt64.from(1))],
    ['sweptTotal', (v) => v.sweptTotal.set(UInt64.from(1))],
    ['expiredTotal', (v) => v.expiredTotal.set(UInt64.from(1))],
    ['sweepCursor', (v) => v.sweepCursor.set(Field(1))],
    ['actionStack', (v) => v.actionStack.set(Field(123))],
    ['actionState', (v) => v.actionState.set(Field(123))],
    ['rootRing', (v) => v.rootRing.set(RootRing.empty().push(Field(123)))],
  ])('is refused with %s prefilled', async (name, write) => {
    expect(failed(await check((await forged({ write })).address))).toEqual([name]);
  });

  it('is refused with a phantom root in the ring, even with the real note root newest', async () => {
    const vault = await forged({
      write: (v) => {
        const real = new NoteTree().root;
        v.rootRing.set(RootRing.empty().push(Field(123)).push(real));
      },
    });
    expect(failed(await check(vault.address))).toEqual(['rootRing']);
  });

  it('is refused with a fake deposit its balance does not back, while pending', async () => {
    const vault = await forged({ write: (v) => dispatch(v, phantomDeposit()) });
    expect(failed(await check(vault.address))).toEqual(['balance']);
  });

  it('is refused with a forged close, or a forged sweep, no deposit explains', async () => {
    expect(failed(await check((await forged({ write: (v) => dispatch(v, forgedClose()) })).address))).toEqual(['actions']);
    const swept = await forged({
      write: (v) => {
        dispatch(v, VaultAction.sweep(UInt64.from(SMALL)));
        v.expiredTotal.set(UInt64.from(SMALL));
      },
    });
    expect(failed(await check(swept.address))).toEqual(['actions']);
  });

  it('is refused with a forged sweep over a deposit that has not expired', async () => {
    const vault = await forged({
      write: (v) => {
        dispatch(v, phantomDeposit(), VaultAction.sweep(UInt64.from(SMALL)));
        v.expiredTotal.set(UInt64.from(SMALL));
      },
    });
    expect(failed(await check(vault.address))).toEqual(['actions']);
  });

  it('is refused with a raise that names no record, which a reduce would make an escape of', async () => {
    const raise = VaultAction.raise(forgedEscape(), { subsidised: Bool(false), tier: Field(MINA) } as never, UInt64.from(MINA));
    const vault = await forged({ write: (v) => dispatch(v, new VaultAction({ ...raise, commitment: Field(0) })) });
    expect(failed(await check(vault.address))).toEqual(['actions']);
  });

  it('is refused with a forged escape no deposit precedes, or a forged finalize of an escape not yet recorded', async () => {
    const pub = forgedClose();
    const escape = new VaultAction({ ...pub, kind: Field(ActionKind.escape), nextNullifier: Field(6) });
    expect(failed(await check((await forged({ write: (v) => dispatch(v, escape) })).address))).toEqual(['actions']);
    const finalize = VaultAction.finalize(escape.pendingEscape(UInt64.from(now() + 2000n)));
    const named = await forged({ write: (v) => dispatch(v, phantomDeposit(), escape, finalize) });
    expect(failed(await check(named.address))).toEqual(['actions']);
  });

  it('is refused with more forged closes pending than notes deposited', async () => {
    const second = new VaultAction({ ...forgedClose(), nullifier: Field(6) });
    const vault = await forged({ write: (v) => dispatch(v, phantomDeposit(), forgedClose(), second) });
    expect(failed(await check(vault.address))).toEqual(['actions']);
  });

});

// Every action queued behind a failing reduce is stuck, so a victim's deposit never becomes a note it could escape with.
describe('a vault whose reduce could never run', () => {
  const backed = (...actions: VaultAction[]) => forged({
    write: (v) => {
      AccountUpdate.createSigned(deployer).send({ to: v.address, amount: UInt64.from(SMALL) });
      dispatch(v, phantomDeposit(), ...actions);
    },
  });
  const close = (over: Partial<VaultAction>) => new VaultAction({ ...forgedClose(), ...over });

  it('passes with the same backed deposit alone, and that one reduces', async () => {
    const vault = await backed();
    expectPass(await check(vault.address));
    await reduceAll(vault);
    expectPass(await check(vault.address));
  });

  it.each<[string, () => VaultAction, string]>([
    ['a deposit conceding more than its amount', () => new VaultAction({ ...phantomDeposit(9n), conceded: UInt64.from(1) }), 'actions'],
    ['a sweep conceding more than its amount', () => new VaultAction({ ...VaultAction.sweep(UInt64.zero), conceded: UInt64.from(1) }), 'actions'],
    ['a close to no account', () => forgedCloseTo(PrivateKey.random().toPublicKey()), 'payee'],
  ])('is refused with %s, which fails the reduce', async (_name, action, refusal) => {
    const vault = await backed(action());
    expect(failed(await check(vault.address))).toEqual([refusal]);
    await expect(reduceAll(vault)).rejects.toThrow();
  });

  it('is refused with more actions in one account update than a batch holds, which no batch can pop', async () => {
    const finalize = VaultAction.finalize(forgedEscape());
    const vault = await forged({ write: (v) => dispatchTogether(v, ...Array<VaultAction>(5).fill(finalize)) });
    // Not reduced here: o1js's `prepareBatches` never gets past such an update, and runs out of memory trying.
    expect(failed(await check(vault.address))).toEqual(['actions']);
  });

  it('is refused with two actions in one account update, which no method dispatches', async () => {
    const vault = await forged({ write: (v) => dispatchTogether(v, phantomDeposit(), phantomDeposit(9n)) });
    expect(failed(await check(vault.address))).toEqual(['actions']);
  });

  it.each<[string, Partial<VaultAction>]>([
    ['a field set that its kind leaves empty', { validUntil: UInt64.from(1) }],
    ['nullifier 0, which is no hash', { nullifier: Field(0) }],
  ])('is refused with %s', async (_name, over) => {
    const vault = await backed(close(over));
    expect(failed(await check(vault.address))).toEqual(['actions']);
  });
});

describe('a read that does not hold up', () => {
  it('refuses when the node or the archive cannot answer, or there is no account', async () => {
    const h = await freshVault();
    const down = async () => { throw Error('unreachable'); };
    for (const r of [{ account: down }, { actions: down }, { events: down }, { slot: down }]) {
      const v = await check(h.vault.address, { reader: { ...reader, ...r } });
      expect(v).toEqual({ pass: false, refusals: [{ check: 'read', detail: 'unreachable' }] });
    }
    expect(failed(await check(PrivateKey.random().toPublicKey()))).toEqual(['read']);
  });

  it.each<[string, Partial<VaultReader>]>([
    ['actions that are not numbers', { actions: async () => [[['not a field']]] }],
    ['actions of the wrong shape', { actions: async () => 'nonsense' as never }],
    ['events that are not numbers', { events: async () => [['not a field']] }],
  ])('refuses an archive that answers with %s', async (_name, lie) => {
    const { vault } = await freshVault();
    expect(failed(await check(vault.address, { reader: { ...reader, ...lie } }))).toEqual(['snapshot']);
  });

  it.each<[string, (l: string[][][]) => string[][][]]>([
    ['leaves out an action', (l) => l.slice(1)],
    ['answers with nothing', () => []],
    ['changes an action', (l) => l.map((x, i) => (i === 0 ? [[x[0]![0]!, '99', ...x[0]!.slice(2)]] : x))],
    ['reorders them', (l) => [...l].reverse()],
    ['adds one', (l) => [...l, l[0]!]],
  ])('refuses an archive that %s', async (_name, lie) => {
    const h = await freshVault();
    await h.deposit(SMALL);
    await h.deposit(SMALL);
    await h.reduce();
    const honest = await reader.actions(h.vault.address);
    expectPass(await check(h.vault.address));
    const v = await check(h.vault.address, { reader: { ...reader, actions: async () => lie(honest) } });
    expect(failed(v)).toEqual(['actionState']);
  });

  it('refuses an archive that gives a wrong deadline, or none, for a pending escape', async () => {
    const h = await freshVault();
    const note = await h.deposit(SMALL);
    await h.reduce();
    await h.escape(await h.withdrawalProof(note, { kind: WithdrawalKind.escape, signed: true, balance: MINA }));
    await h.reduce();
    expectPass(await check(h.vault.address));
    const events = await reader.events(h.vault.address);
    const later = events.map((e) => [...e.slice(0, -1), String(BigInt(e.at(-1)!) + 1n)]);
    expect(failed(await check(h.vault.address, { reader: { ...reader, events: async () => later } }))).toEqual(['pendingEscapesRoot']);
    expect(failed(await check(h.vault.address, { reader: { ...reader, events: async () => [] } }))).toEqual(['actions']);
  });
});

// A limit, not a guarantee (ADR 0008, "What a pass doesn't show"). If this test fails, the limit may have gone, and
// the ADR should say so.
describe('what a pass does not show', () => {
  it("passes a vault whose forged close hides a phantom note, which then takes a victim's deposit", async () => {
    const stateKey = PrivateKey.random();
    const secret = 4242n;
    const deposit = phantomDeposit(secret);
    const close = forgedClose();
    const vault = await forged({
      stateKey: stateKey.toPublicKey(),
      write: (v) => {
        writeReducedDeposit(v, deposit);
        dispatch(v, close);
        const nullifiers = new NullifierSet();
        nullifiers.insert(close.nullifier, 1n);
        v.nullifierRoot.set(nullifiers.root);
        v.claimedTotal.set(close.size);
        // As if a reduce had folded both.
        v.actionState.set([deposit, close].reduce(
          (acc, a) => AccountUpdate.Actions.updateSequenceState(acc, AccountUpdate.Actions.fromList([VaultAction.toFields(a)]).hash), emptyStack
        ));
      },
    });
    expect(await check(vault.address)).toEqual({ pass: true, dispatched: 2, reduced: 2 });

    // A victim deposits. The check still passes: the books say the vault holds what it owes.
    const signedDeposit = await Mina.transaction(payer, async () => {
      await vault.deposit(commitSecret(Field(1n)), UInt64.from(SMALL), UInt64.from(now()));
    });
    await signedDeposit.prove();
    await signedDeposit.sign([payer.key]).send();
    expect(balanceOf(vault.address)).toBe(SMALL);
    expectPass(await check(vault.address));

    // The deployer closes the phantom note for real: its leaf is in the tree and its own nullifier is unspent.
    const before = balanceOf(bob);
    await reduceAll(vault);
    const view = await vaultView(vault);
    const { pub, priv } = buildWithdrawal(view.tree, {
      kind: WithdrawalKind.mutualClose, secret, index: 0n, size: SMALL, depositTime: deposit.time.toBigInt(), requestTime: now(),
      signed: false, balance: SMALL, blinding: 99n, stateKey, destination: bob,
    });
    const { proof } = await WithdrawalProgram.mutualClose(pub, priv);
    const clearance = signClearance(stateKey, { stateKey: stateKey.toPublicKey(), nullifier: pub.nullifier, destination: pub.destination });
    const tx = await Mina.transaction(payer, async () => {
      await vault.mutualClose(proof, clearance, view.nullifiers.clone());
    });
    await tx.prove();
    await tx.sign([payer.key]).send();
    await reduceAll(vault);
    expect(balanceOf(bob)).toBe(before + SMALL);
    expect(balanceOf(vault.address)).toBe(0n);
  });
});

describe('the published vectors', () => {
  const { cases } = JSON.parse(readFileSync(new URL('../../test-vectors/vault-check.json', import.meta.url), 'utf8')) as {
    cases: { name: string; codeHash: string; snapshot: VaultSnapshot; refuses: string[] }[];
  };
  it('cover a pass and a refusal', () => {
    expect(cases.some((c) => c.refuses.length === 0)).toBe(true);
    expect(cases.some((c) => c.refuses.length > 0)).toBe(true);
  });
  it.each(cases.map((c) => [c.name, c] as const))('answer as recorded: %s', (_name, c) => {
    expect(failed(judgeVault(c.snapshot, c.codeHash))).toEqual(c.refuses);
  });
});
