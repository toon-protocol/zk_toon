// Proves the real `Vault` and the action-stack program on a LocalBlockchain, with the o1js dump patch on
// (SPIKE_DUMP, light mode), as the Rust wrap prover's reference. Run by `regenerate.sh --vault`, in three
// processes (see its comment for why): `compile`, `main` and `recursive`.
//   vault-fixtures.ts compile <cache dir> <out dir>      compile with an empty cache: every circuit is dumped
//   vault-fixtures.ts main <cache dir> <out dir>         prove the nine vault methods
//   vault-fixtures.ts recursive <cache dir> <out dir>    prove the real action-stack chunks, then `reduce` from them
// Each writes `<out dir>/manifest.json`: for each case, the ranges of o1js's step proofs and witnesses it made.
import fs from 'node:fs';
import { AccountUpdate, Cache, Field, Mina, UInt64, Unconstrained } from 'o1js';
import * as policy from '../o1js/src/policy.js';
import { CLOSE_WINDOW_SLOTS, Vault, batchReducer } from '../o1js/src/vault.js';
import { RequestProgram } from '../o1js/src/request.js';
import { WithdrawalKind, WithdrawalProgram } from '../o1js/src/withdrawal.js';
import { vaultHarness, now } from '../o1js/src/vault-harness.js';
import { provableBatches } from '../o1js/src/vault-view.js';
import { published } from '../o1js/src/keys.js';

const [mode, cacheDir, out] = process.argv.slice(2);
if (!process.env.SPIKE_DUMP || !process.env.SPIKE_DUMP_LIGHT) throw Error('run with SPIKE_DUMP and SPIKE_DUMP_LIGHT set');
fs.mkdirSync(out, { recursive: true });

const [SMALL] = policy.DEPOSIT_SIZES;
const [, , TOP_TIER] = policy.TIERS;
const MINA = 1_000_000_000n;
const LIMIT = batchReducer.maxUpdatesFinalProof;
const CHUNK = batchReducer.program.maxUpdatesPerProof;

const cache = Cache.FileSystem(cacheDir);
// The vault's `import 'o1js'` is this package's, so these are the one o1js's.
const keys: Record<string, { data: string; hash: string }> = {};
const compileAll = async () => {
  keys.request = published((await RequestProgram.compile({ cache })).verificationKey);
  keys.withdrawal = published((await WithdrawalProgram.compile({ cache })).verificationKey);
  const reducer = await (batchReducer.program.compile as (o: { cache: Cache }) => ReturnType<typeof batchReducer.compile>)({ cache });
  keys.vaultReducer = published(reducer.verificationKey);
  keys.vault = published((await Vault.compile({ cache })).verificationKey);
};

if (mode === 'compile') {
  await compileAll();
  fs.writeFileSync(`${out}/keys.json`, JSON.stringify(keys));
  process.exit(0);
}

// What o1js's step proofs and witnesses are numbered by: the patch counts them from 1 in each process.
const counter = (n: '__spikeP' | '__spikeW') => ((globalThis as any)[n] ?? 0) as number;
const manifest: { name: string; proofs: [number, number]; witnesses: [number, number] }[] = [];
// The zkApp public input (`accountUpdate`, `calls`) o1js proves each call under: the wrap proof's public input
// is not in the step proof's, which holds only its hash.
const zkappInputs: { accountUpdate: Field; calls: Field }[] = [];
const toPublicInput = AccountUpdate.prototype.toPublicInput;
AccountUpdate.prototype.toPublicInput = function (this: AccountUpdate, ...args: Parameters<typeof toPublicInput>) {
  const input = toPublicInput.apply(this, args);
  // Only the account updates that carry a proof (the fee payer and signed updates are hashed the same way).
  if (this.body.authorizationKind.isProved.toBoolean()) zkappInputs.push(input);
  return input;
};
/**
 * Runs `fn` and records the step proofs and witnesses o1js made meanwhile as case `name`, with the zkApp public
 * input of its call and `previous`, the proof its method verifies (`<name>_previous.json`).
 */
async function capture<T>(name: string, fn: () => Promise<T>, previous?: { toJSON(): unknown }): Promise<T> {
  const [p, w] = [counter('__spikeP'), counter('__spikeW')];
  zkappInputs.length = 0;
  const result = await fn();
  const distinct = [...new Set(zkappInputs.map((i) => `${i.accountUpdate.toString()},${i.calls.toString()}`))];
  // The chunk proofs are not a call: no zkApp public input.
  if (distinct.length > 1) throw Error(`${name}: expected one zkApp public input, saw ${distinct.length}`);
  if (distinct.length === 1) fs.writeFileSync(`${out}/${name}_zkapp_public.json`, JSON.stringify(distinct[0].split(',')));
  if (previous) fs.writeFileSync(`${out}/${name}_previous.json`, JSON.stringify(previous.toJSON()));
  manifest.push({ name, proofs: [p + 1, counter('__spikeP')], witnesses: [w + 1, counter('__spikeW')] });
  return result;
}

await compileAll();
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
const { payer, alice, bob, advance, freshVault } = vaultHarness(Local);
/** Runs `fn` with proofs on, the chain's default being off. */
async function proved<T>(fn: () => Promise<T>): Promise<T> {
  Local.setProofsEnabled(true);
  try {
    return await fn();
  } finally {
    Local.setProofsEnabled(false);
  }
}
/** Pays `payer` from the other test accounts, so it can make many deposits. */
async function topUp(n: bigint) {
  for (const from of Local.testAccounts.slice(2, 2 + Number((n + 499n) / 500n))) {
    const tx = await Mina.transaction(from, async () => {
      AccountUpdate.createSigned(from).send({ to: payer, amount: UInt64.from(500n * MINA) });
    });
    await tx.sign([from.key]).send();
  }
}
// A vault under its own key (the registry has its own circuit, which no fixture needs), deployed with proofs
// on so it carries the real key its methods are checked against.
const deploy = () => proved(() => freshVault({ setup: false, direct: true }));

async function main() {
  const h = await deploy();
  await capture('setup', () => proved(() => h.setup()));
  // The first note expires and is swept last; the others are deposited at the same slot.
  const expiring = await capture('deposit', () => proved(() => h.deposit(SMALL)));
  const [a, b, c, d] = [await h.deposit(SMALL), await h.deposit(SMALL), await h.deposit(SMALL), await h.deposit(SMALL)];
  // Five action lists: the first batch is proved, with a dummy action-stack proof, and the rest are not.
  const reduce = async (proven: boolean) => {
    batchReducer.setContractInstance(h.vault);
    let first = true;
    for (const { batch, proof } of await provableBatches()) {
      const t = now();
      const { witnesses, nullifiers, escapes } = h.mirror.nextReduce(t);
      const send = async () =>
        h.send(
          await Mina.transaction(payer, async () => {
            await h.vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(t));
          })
        );
      if (proven && first) await capture('reduce', () => proved(send), proof);
      else await send();
      first = false;
    }
  };
  await reduce(true);

  const { escape: ESCAPE, mutualClose } = WithdrawalKind;
  const close = await h.withdrawalProof(a, { kind: mutualClose, signed: true, step: 1, balance: 4n * MINA, destination: bob });
  await capture('mutualClose', () => proved(() => h.close(close)), close);
  // Three escapes: `finalize` pays one, `defeat` and `raise` challenge the others.
  const genesis = (note: typeof b) => h.withdrawalProof(note, { kind: ESCAPE, signed: false, step: 0, balance: SMALL, destination: alice });
  const [toFinalize, toDefeat] = [await genesis(b), await genesis(c)];
  const toRaise = await h.withdrawalProof(d, { kind: ESCAPE, signed: true, step: 1, balance: 3n * MINA, conceded: MINA / 100n, destination: alice });
  await capture('escape', () => proved(() => h.escape(toFinalize)), toFinalize);
  await h.escape(toDefeat);
  await h.escape(toRaise);
  await reduce(false);

  const defeatEvidence = await h.requestProof(c, { step: 1, balance: 4n * MINA, tier: TOP_TIER });
  await capture('defeat', () => proved(() => h.defeat(toDefeat.publicInput.nullifier, defeatEvidence)), defeatEvidence);
  const raiseEvidence = await h.requestProof(d, { balance: 3n * MINA, tier: TOP_TIER });
  await capture('raise', () => proved(() => h.raise(toRaise.publicInput.nullifier, raiseEvidence, MINA / 2n)), raiseEvidence);
  advance(h.mirror.pendingEscape(toFinalize.publicInput.nullifier)!.deadline.toBigInt() - now());
  await capture('finalize', () => proved(() => h.finalize(toFinalize.publicInput.nullifier)));

  advance(expiring.depositTime + policy.NOTE_LIFETIME_SLOTS + CLOSE_WINDOW_SLOTS - now());
  await capture('sweepExpired', () => proved(() => h.sweep()));
}

async function recursive() {
  const h = await deploy();
  await h.setup();
  // `LIMIT` action lists go to the reduce itself; the rest need two chunks, the second proved from the first.
  const lists = LIMIT + CHUNK + 1;
  await topUp(BigInt(lists) * (SMALL / MINA));
  for (let i = 0; i < lists; i++) await h.deposit(SMALL);
  batchReducer.setContractInstance(h.vault);
  // `provableBatches` proves the chunks last first: the last from the 2^15 dummy, then the one before from it.
  const batches = await capture('chunks', () => proved(provableBatches));
  let index = 0;
  for (const { batch, proof } of batches) {
    const t = now();
    const { witnesses, nullifiers, escapes } = h.mirror.nextReduce(t);
    const send = async () =>
      h.send(
        await Mina.transaction(payer, async () => {
          await h.vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(t));
        })
      );
    if (index++ === 0) await capture('reduceRecursive', () => proved(send), proof);
    else await send();
  }
}

if (mode === 'main') await main();
else if (mode === 'recursive') await recursive();
else throw Error(`unknown mode ${mode}`);
fs.writeFileSync(`${out}/manifest.json`, JSON.stringify(manifest, null, 1));
fs.writeFileSync(`${out}/keys.json`, JSON.stringify(keys));
process.exit(0);
