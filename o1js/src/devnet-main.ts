// `npm run devnet -- <run>`: deploys a vault to Mina devnet and walks it through the smoke test of #17,
// paying from the dev funder. Safe to run again: it reads what the run's journal says is done and carries on,
// and it stops, saying when to come back, while the escape's challenge window is open. See `docs/devnet-smoke.md`.
//
// TOON_FUNDER_MNEMONIC stays in memory, and so do the run's keys and notes, derived from it. The journal
// holds only what is public.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { AccountUpdate, Field, Mina, PrivateKey, PublicKey, Scalar, Signature, UInt32, UInt64, Unconstrained, fetchAccount, fetchLastBlock } from 'o1js';
import { commit } from './balance.js';
import { signClearance } from './clearance.js';
import { type Clock, minaKeyFromMnemonic, runKey, runSecret, sendPlan, targetSlot } from './devnet.js';
import { buildKeys } from './keys.js';
import { DEPOSIT_SIZES, SLOT_SECONDS, TIERS } from './policy.js';
import { commitSecret, genesisAnchor, nullifier } from './primitives.js';
import { stateChain } from './request-sample.js';
import { stateFields } from './state.js';
import { createBuilder } from './tx-builder.js';
import { VAULT_URI, Vault, batchReducer, setupFields } from './vault.js';
import { pendingEscapesView, provableBatches, reduceMirror } from './vault-view.js';

const MINA_URL = process.env.MINA_GRAPHQL ?? 'https://devnet-plain-1.gcp.o1test.net/graphql';
const ARCHIVE_URL = process.env.MINA_ARCHIVE ?? 'https://devnet-archive-node-api.gcp.o1test.net';
const FUNDER_ADDRESS = 'B62qp9YT9mw27enrwPR3gSPeRkXxAg1runhKK7mx6jj64Lq6EukJRTy';
const FEE = 100_000_000n;
const MAX_ATTEMPTS = 6;
const INCLUSION_TIMEOUT_MS = 40 * 60_000;

const run = process.argv[2];
if (!run || !/^[a-z0-9-]+$/.test(run)) {
  console.error('usage: npm run devnet -- <run name>');
  process.exit(2);
}
const mnemonic = process.env.TOON_FUNDER_MNEMONIC;
if (!mnemonic) throw Error('TOON_FUNDER_MNEMONIC is not set');
const funderKey = minaKeyFromMnemonic(mnemonic);
const funder = funderKey.toPublicKey();
if (funder.toBase58() !== FUNDER_ADDRESS) throw Error(`the mnemonic derives ${funder.toBase58()}, not the dev funder`);

// --- The run's keys and notes. ---
const own = (label: string) => runSecret(funderKey.toBigInt(), run, label);
const key = (label: string) => runKey(funderKey.toBigInt(), run, label);
const upgradeKey = key('vault');
const stateKey = key('state');
const treasuryKey = key('treasury');
const destinationKey = key('destination');
const [vaultAddress, treasury, destination] = [upgradeKey, treasuryKey, destinationKey].map((k) => k.toPublicKey()) as [PublicKey, PublicKey, PublicKey];
const vault = new Vault(vaultAddress);
const SIZE = DEPOSIT_SIZES[0]!;
const TIER = TIERS[1]!;
const CONCEDED = TIERS[0]!;
const closeBalance = SIZE - TIER;

// --- The journal: public facts only, kept beside the write-up. ---
type Attempt = {
  step: string; hash: string; target?: string; sentSlot?: string; landedSlot?: string; height?: string;
  proveSeconds?: number; inclusionSeconds?: number; failure?: unknown; fee: string;
};
type Journal = { run: string; vault: string; funder: string; treasury: string; destination: string; facts: Record<string, unknown>; done: string[]; attempts: Attempt[]; sent?: { step: string; hash: string } };
const journalDir = new URL('../../docs/devnet-smoke/', import.meta.url);
const journalPath = new URL(`${run}.json`, journalDir);
const journal: Journal = existsSync(journalPath)
  ? JSON.parse(readFileSync(journalPath, 'utf8'))
  : { run, vault: vaultAddress.toBase58(), funder: FUNDER_ADDRESS, treasury: treasury.toBase58(), destination: destination.toBase58(), facts: {}, done: [], attempts: [] };
const saveJournal = () => {
  mkdirSync(journalDir, { recursive: true });
  writeFileSync(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
};
const log = (message: string) => console.log(`${new Date().toISOString()} ${message}`);

// --- The chain. ---
async function graphql<T>(query: string, variables: object = {}): Promise<T> {
  const response = await fetch(MINA_URL, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query, variables }),
  });
  const body = (await response.json()) as { data?: T; errors?: unknown };
  if (!body.data) throw Error(`GraphQL: ${JSON.stringify(body.errors)}`);
  return body.data;
}
type Block = {
  protocolState: { consensusState: { slotSinceGenesis: string; blockHeight: string }; blockchainState: { utcDate: string } };
  transactions: { zkappCommands: { hash: string; failureReason: unknown }[] };
};
const BLOCK = `protocolState { consensusState { slotSinceGenesis blockHeight } blockchainState { utcDate } }
  transactions { zkappCommands { hash failureReason { index failures } } }`;
const bestChain = async (length: number) => (await graphql<{ bestChain: Block[] }>(`{ bestChain(maxLength: ${length}) { ${BLOCK} } }`)).bestChain;
async function clock(): Promise<Clock> {
  const tip = (await bestChain(1))[0]!.protocolState;
  return { tipSlot: BigInt(tip.consensusState.slotSinceGenesis), tipMs: Number(tip.blockchainState.utcDate) };
}
/** The slot the wall clock is in, which is ahead of the tip's when the last slots had no block. */
async function wallSlot() {
  const c = await clock();
  return targetSlot(c, Date.now(), 0) - 1n;
}
async function balance(account: PublicKey) {
  const { account: a } = await graphql<{ account: { balance: { total: string } } | null }>(
    `query($k: PublicKey!) { account(publicKey: $k) { balance { total } } }`, { k: account.toBase58() }
  );
  return BigInt(a?.balance.total ?? 0);
}
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits for `hash` in the best chain; a command that fails is included too, and charged. */
async function inclusion(hash: string) {
  const deadline = Date.now() + INCLUSION_TIMEOUT_MS;
  while (Date.now() < deadline) {
    for (const block of await bestChain(290)) {
      const found = block.transactions.zkappCommands.find((c) => c.hash === hash);
      if (found) return { block, failure: found.failureReason };
    }
    await sleep(15_000);
  }
  throw Error(`${hash} was not included within ${INCLUSION_TIMEOUT_MS / 60_000} minutes; if it was dropped, remove \`sent\` from the journal before running again`);
}

const proveEstimates = new Map<string, number>();
/** `currentSlot`, the vault's only read of chain time, is the command's `validWhile`. */
const isSlotMiss = (failure: unknown) => JSON.stringify(failure).includes('Valid_while_precondition_unsatisfied');

/**
 * A run stopped while a command was out: that command decides, so a resume doesn't send a second one.
 * True if `step`'s command was out and applied; a slot miss is journalled, and leaves the step to try again.
 */
async function settleSent(step: string) {
  if (journal.sent?.step !== step) return false;
  const { hash } = journal.sent;
  log(`${step}: looking for ${hash}, sent before this run stopped`);
  const { block, failure } = await inclusion(hash);
  const { slotSinceGenesis, blockHeight } = block.protocolState.consensusState;
  journal.attempts.push({ step, hash, landedSlot: slotSinceGenesis, height: blockHeight, failure: failure ?? undefined, fee: FEE.toString() });
  delete journal.sent;
  saveJournal();
  if (failure && !isSlotMiss(failure)) throw Error(`${step}: failed on chain: ${JSON.stringify(failure)}`);
  return !failure;
}

/**
 * Proves and lands one command, journalling each attempt. `build` gets the slot to aim at. With `aimed`, the
 * command is held back to reach that slot's block, and proved again if proving overran; a command that misses
 * its slot range is included as failed, and is tried again.
 */
async function land(step: string, build: (target: bigint) => Promise<object>, { aimed = true } = {}) {
  if (await settleSent(step)) return;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const started = Date.now();
    const target = targetSlot(await clock(), started, proveEstimates.get(step) ?? 240_000);
    log(`${step}: attempt ${attempt}, aiming at slot ${target}`);
    const command = await build(target);
    const proveMs = Date.now() - started;
    proveEstimates.set(step, proveMs);

    if (aimed) {
      let plan = sendPlan(await clock(), Date.now(), target);
      while (plan.kind === 'wait') {
        await sleep(plan.ms);
        plan = sendPlan(await clock(), Date.now(), target);
      }
      if (plan.kind === 'late') {
        log(`${step}: proving took ${Math.round(proveMs / 1000)} s and overran slot ${target}, proving again`);
        attempt--;
        continue;
      }
    }

    const pending = await Mina.Transaction.fromJSON(command as never).send();
    if (pending.status === 'rejected') throw Error(`${step}: refused: ${JSON.stringify(pending.errors)}`);
    const sentMs = Date.now();
    journal.sent = { step, hash: pending.hash };
    saveJournal();
    const sentSlot = await wallSlot();
    log(`${step}: sent ${pending.hash}`);
    const { block, failure } = await inclusion(pending.hash);
    const entry: Attempt = {
      step, hash: pending.hash, target: aimed ? target.toString() : undefined, sentSlot: sentSlot.toString(),
      landedSlot: block.protocolState.consensusState.slotSinceGenesis, height: block.protocolState.consensusState.blockHeight,
      proveSeconds: Math.round(proveMs / 1000), inclusionSeconds: Math.round((Date.now() - sentMs) / 1000),
      failure: failure ?? undefined, fee: FEE.toString(),
    };
    journal.attempts.push(entry);
    delete journal.sent;
    saveJournal();
    if (!failure) {
      log(`${step}: applied in slot ${entry.landedSlot}, block ${entry.height}`);
      return;
    }
    log(`${step}: failed in slot ${entry.landedSlot}: ${JSON.stringify(failure)}`);
    if (!isSlotMiss(failure)) throw Error(`${step}: failed on chain: ${JSON.stringify(failure)}`);
  }
  throw Error(`${step}: missed its slot range ${MAX_ATTEMPTS} times`);
}

/** Runs a step once across resumes. */
async function step(name: string, body: () => Promise<void>) {
  if (journal.done.includes(name)) return;
  await body();
  journal.done.push(name);
  saveJournal();
}

const payer = { sender: funder, fee: UInt64.from(FEE) };
const refresh = async (...accounts: PublicKey[]) => {
  for (const publicKey of [funder, vaultAddress, ...accounts]) await fetchAccount({ publicKey });
};
async function sealed(tx: Awaited<ReturnType<typeof Mina.transaction>>, keys: PrivateKey[] = []) {
  await tx.prove();
  return JSON.parse(tx.sign([funderKey, ...keys]).toJSON()) as object;
}

// --- The builder's operations, as the wallet calls them. ---
const builder = await createBuilder({ local: false, proofs: true, mina: MINA_URL, archive: ARCHIVE_URL });
const network = Mina.Network({ mina: MINA_URL, archive: ARCHIVE_URL });
Mina.setActiveInstance(network);
let nextId = 0;
async function op<T>(name: string, params: object): Promise<T> {
  const answer = JSON.parse(await builder.handle(JSON.stringify({ id: nextId++, op: name, params })));
  if (!answer.ok) throw Error(`${name}: ${answer.error.kind}: ${answer.error.message}`);
  return answer.result as T;
}
const feePayer = () => ({ privateKey: funderKey.toBase58(), fee: FEE.toString() });

// --- The two notes. ---
const noteOf = (label: string) => {
  const secret = own(`note/${label}`);
  return { secret, commitment: commitSecret(Field(secret)) };
};
const closing = noteOf('close');
const escaping = noteOf('escape');
const noteParam = (n: { secret: bigint }, depositTime: string) => ({ secret: n.secret.toString(), size: SIZE.toString(), depositTime });
const genesisState = (label: string) => ({ blinding: own(`blinding/${label}`).toString(), signed: null });

/** The balances the payouts are measured against, journalled at each step. */
const payees = async () => ({ destination: (await balance(destination)).toString(), treasury: (await balance(treasury)).toString() });

/** Reduces every pending action, one command per batch. */
async function reduceAll(name: string) {
  if (journal.sent?.step.startsWith(`${name}-`) && (await settleSent(journal.sent.step))) return;
  for (let waited = 0; ; waited++) {
    await refresh();
    batchReducer.setContractInstance(vault);
    const { pending } = await reduceMirror(vault);
    const want = journal.facts[`${name}.actions`] as number | undefined;
    if (want !== undefined && pending >= want) break;
    if (waited > 40) throw Error(`${name}: the archive shows ${pending} pending actions, not ${want}`);
    await sleep(30_000);
  }
  await refresh();
  const batches = await provableBatches();
  log(`${name}: ${batches.length} batch(es) to reduce`);
  for (const [i, { batch, proof }] of batches.entries()) {
    await land(`${name}-${i}`, async (target) => {
      await refresh(treasury, destination);
      const { mirror } = await reduceMirror(vault);
      const { witnesses, nullifiers, escapes } = mirror.nextReduce(target);
      const tx = await Mina.transaction(payer, async () => {
        await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(target));
      });
      return sealed(tx);
    });
  }
}

const expectGrowth = (name: string, before: { destination: string; treasury: string }, after: { destination: string; treasury: string }, toDestination: bigint, toTreasury: bigint) => {
  const got = [BigInt(after.destination) - BigInt(before.destination), BigInt(after.treasury) - BigInt(before.treasury)];
  if (got[0] !== toDestination || got[1] !== toTreasury) {
    throw Error(`${name}: paid ${got[0]} and ${got[1]}, not ${toDestination} and ${toTreasury}`);
  }
};

// --- The smoke test. ---
log(`run ${run}: vault ${vaultAddress.toBase58()}, funder balance ${await balance(funder)}`);
const keys = await buildKeys();
// What the run deployed is what it records: a later build of other code can't drive this vault.
if (journal.facts.vaultCodeHash !== undefined && journal.facts.vaultCodeHash !== keys.vault.codeHash) {
  throw Error(`this build's vault code hash ${keys.vault.codeHash} is not the deployed ${journal.facts.vaultCodeHash}`);
}
journal.facts.o1js = keys.o1js;
journal.facts.vaultCodeHash = keys.vault.codeHash;
journal.facts.requestKeyHash = keys.circuits.request.verificationKey.hash;
journal.facts.withdrawalKeyHash = keys.circuits.withdrawal.verificationKey.hash;
journal.facts.reducerKeyHash = keys.circuits.vaultReducer.verificationKey.hash;
saveJournal();

await step('accounts', () => land('accounts', async () => {
  await refresh();
  const tx = await Mina.transaction(payer, async () => {
    AccountUpdate.fundNewAccount(funder, 2);
    const from = AccountUpdate.createSigned(funder);
    from.send({ to: treasury, amount: 1_000_000_000n });
    from.send({ to: destination, amount: 1_000_000_000n });
  });
  return sealed(tx);
}, { aimed: false }));

await step('deploy', () => land('deploy', async (target) => {
  await refresh();
  await fetchLastBlock();
  // `init` pins the creation slot to the slot o1js reports, so it reports the slot this command is aimed at.
  Mina.setActiveInstance({
    ...network, getNetworkState: () => ({ ...network.getNetworkState(), globalSlotSinceGenesis: UInt32.from(target) }),
  });
  try {
    const tx = await Mina.transaction(payer, async () => {
      AccountUpdate.fundNewAccount(funder);
      await vault.deploy({ zkappUri: VAULT_URI });
    });
    return await sealed(tx, [upgradeKey]);
  } finally {
    Mina.setActiveInstance(network);
  }
}));

await step('setup', () => land('setup', async () => {
  await refresh(treasury);
  const statePub = stateKey.toPublicKey();
  const signature = Signature.create(upgradeKey, setupFields(vaultAddress, statePub, treasury));
  const tx = await Mina.transaction(payer, async () => {
    await vault.setup(statePub, treasury, signature);
  });
  return sealed(tx);
}, { aimed: false }));

for (const [label, note] of [['close', closing], ['escape', escaping]] as const) {
  await step(`deposit-${label}`, () => land(`deposit-${label}`, async (target) => {
    const { zkappCommand } = await op<{ zkappCommand: object }>('deposit', {
      vault: vaultAddress.toBase58(), feePayer: feePayer(), commitment: note.commitment.toString(), size: SIZE.toString(), depositTime: target.toString(),
    });
    journal.facts[`depositTime.${label}`] = target.toString();
    return zkappCommand;
  }));
}

journal.facts['reduce-deposits.actions'] = 2;
await step('reduce-deposits', () => reduceAll('reduce-deposits'));

const depositTime = (label: string) => journal.facts[`depositTime.${label}`] as string;

await step('request-proof', async () => {
  const requestTime = await wallSlot();
  const started = Date.now();
  const { proof, publicInputFields } = await op<{ proof: { publicInput: string[] }; publicInputFields: string[] }>('requestProof', {
    vault: vaultAddress.toBase58(), note: noteParam(closing, depositTime('close')), state: genesisState('close'),
    requestTime: requestTime.toString(), tier: TIER.toString(), rerandomBlinding: own('rerandom').toString(),
    sessionKey: key('session').toPublicKey().toBase58(), requestExpiry: (requestTime + 7n).toString(),
  });
  const proveSeconds = Math.round((Date.now() - started) / 1000);
  const { valid } = await op<{ valid: boolean }>('verifyRequestProof', { proof });
  await refresh();
  const root = vault.noteRoot.get().toString();
  if (!valid || publicInputFields[2] !== root) throw Error(`request proof: valid ${valid}, its root ${publicInputFields[2]}, the vault's ${root}`);
  journal.facts.requestProof = { requestTime: requestTime.toString(), root, valid, proveSeconds };
});

await step('close', async () => {
  journal.facts['payees.before-exits'] ??= await payees();
  const secret = Field(closing.secret);
  const { anchor, prevAnchor } = stateChain(secret, 1);
  const statePub = stateKey.toPublicKey();
  const blinding = own('blinding/close-1');
  const commitment = commit(Scalar.from(closeBalance), Scalar.from(blinding));
  const signed = Signature.create(stateKey, stateFields({ vault: statePub, commitment, anchor }));
  const clearance = signClearance(stateKey, { stateKey: statePub, nullifier: nullifier(secret, anchor), destination });
  const encode = (s: Signature) => ({ r: s.r.toString(), s: s.s.toBigInt().toString() });
  await land('close', async () => {
    const { zkappCommand } = await op<{ zkappCommand: object }>('mutualClose', {
      vault: vaultAddress.toBase58(), feePayer: feePayer(), note: noteParam(closing, depositTime('close')),
      state: { blinding: blinding.toString(), signed: { balance: closeBalance.toString(), prevAnchor: prevAnchor.toString(), signature: encode(signed) } },
      requestTime: (await wallSlot()).toString(), destination: destination.toBase58(), clearance: encode(clearance),
    });
    return zkappCommand;
  }, { aimed: false });
});

await step('escape', () => land('escape', async () => {
  const requestTime = await wallSlot();
  const { zkappCommand } = await op<{ zkappCommand: object }>('escape', {
    vault: vaultAddress.toBase58(), feePayer: feePayer(), note: noteParam(escaping, depositTime('escape')), state: genesisState('escape'),
    requestTime: requestTime.toString(), destination: destination.toBase58(), conceded: CONCEDED.toString(), validUntil: (requestTime + 20n).toString(),
  });
  return zkappCommand;
}, { aimed: false }));

journal.facts['reduce-exits.actions'] = 2;
await step('reduce-exits', async () => {
  await reduceAll('reduce-exits');
  await sleep(30_000);
  const after = await payees();
  journal.facts['payees.after-close'] = after;
  expectGrowth('close', journal.facts['payees.before-exits'] as never, after, closeBalance, SIZE - closeBalance);
});

const escapingNullifier = nullifier(Field(escaping.secret), genesisAnchor(escaping.commitment));
const pendingEscape = async () => {
  await refresh();
  const { escapes, records } = await pendingEscapesView(vault, { localChain: false });
  return { escapes, record: records.get(escapingNullifier.toBigInt()) };
};

if (!journal.done.includes('finalize')) {
  const { record } = await pendingEscape();
  if (!record) throw Error('the escape is not pending');
  const deadline = record.deadline.toBigInt();
  journal.facts.escapeDeadline = deadline.toString();
  const slot = await wallSlot();
  saveJournal();
  if (slot < deadline) {
    const hours = (Number(deadline - slot) * Number(SLOT_SECONDS)) / 3600;
    log(`the escape's window is open until slot ${deadline}, now ${slot}: about ${hours.toFixed(1)} hours. Run this again after that.`);
    process.exit(0);
  }
}

await step('finalize', () => land('finalize', async () => {
  const { escapes, record } = await pendingEscape();
  const tx = await Mina.transaction(payer, async () => {
    await vault.finalize(record!, escapes.clone());
  });
  return sealed(tx);
}, { aimed: false }));

journal.facts['reduce-final.actions'] = 1;
await step('reduce-final', async () => {
  await step('reduce-final-landed', () => reduceAll('reduce-final'));
  await sleep(30_000);
  const after = await payees();
  journal.facts['payees.after-finalize'] = after;
  expectGrowth('finalize', journal.facts['payees.after-close'] as never, after, SIZE - CONCEDED, CONCEDED);
});

await step('refund', () => land('refund', async () => {
  await refresh(treasury, destination);
  const [t, d] = [await balance(treasury), await balance(destination)];
  const tx = await Mina.transaction(payer, async () => {
    AccountUpdate.createSigned(treasury).send({ to: funder, amount: t });
    AccountUpdate.createSigned(destination).send({ to: funder, amount: d });
  });
  return sealed(tx, [treasuryKey, destinationKey]);
}, { aimed: false }));

log(`run ${run}: every step is done. Funder balance ${await balance(funder)}`);
process.exit(0);
