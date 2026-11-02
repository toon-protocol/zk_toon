// Runs a real vault on the proofs-on lightnet and records what its daemon and archive answer (#67): a
// vault with two reduced notes, one of them escaped. The note left unspent is the one the request-proof
// fixtures are proved for, so the recording and the proofs describe one chain.
//
// The vault's deposit and reduce must land within two slots of a slot they name, and proving outlasts that.
// So a transaction names a slot far enough ahead to prove in, waits for it, and is built again if it misses.
import { AccountUpdate, Field, Mina, PrivateKey, Signature, UInt64, Unconstrained, fetchAccount } from 'o1js';
import type { NoteTree } from './note-tree.js';
import { DEPOSIT_SIZES } from './policy.js';
import { commitSecret } from './primitives.js';
import { RequestProgram } from './request.js';
import { VAULT_URI, Vault, batchReducer, setupFields } from './vault.js';
import { actions, provableBatches, vaultView } from './vault-view.js';
import { WithdrawalKind, WithdrawalProgram } from './withdrawal.js';
import { buildWithdrawal } from './withdrawal-sample.js';

const FEE = 100_000_000;
/** The lightnet's slot. */
const SLOT_MS = 20_000;
/** How many times a transaction is built again before the run gives up. */
const ATTEMPTS = 12;
/** How long after its request slot the escape may land: long enough to prove it and to retry. */
const ESCAPE_VALIDITY_SLOTS = 60n;

type Tx = Awaited<ReturnType<typeof Mina.transaction>>;
export type Endpoints = { mina: string; archive: string };

/** What the daemon and the archive answered, in the shapes the challenger adapter reads. */
export interface VaultRecording {
  about: string;
  vault: string;
  vaultState: unknown;
  actions: unknown;
  escapeEvents: unknown;
}

export interface RecordedVault {
  recording: VaultRecording;
  /** The vault's note tree, and the unspent note the proofs are for. */
  tree: NoteTree;
  index: bigint;
  note: { secret: bigint; size: bigint; depositTime: bigint };
  stateKey: PrivateKey;
  creationTime: bigint;
  /** The chain tip's slot in the recording. */
  slot: bigint;
  /** The nullifier the escaped note's action consumed. */
  consumedNullifier: Field;
}

async function graphql(url: string, operationName: string, query: string, variables: Record<string, unknown> = {}) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ operationName, query, variables }),
  });
  if (!response.ok) throw Error(`${operationName}: ${response.status} ${await response.text()}`);
  const body = await response.json();
  if (body.errors) throw Error(`${operationName}: ${JSON.stringify(body.errors)}`);
  return body;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Deploys a vault and takes it through deposits, a reduce, an escape and a reduce, then records it. */
export async function recordVault(
  endpoints: Endpoints, sender: Mina.TestPublicKey, log: (line: string) => void = console.log,
): Promise<RecordedVault> {
  /**
   * The slot the daemon's clock is in, which may be past the tip's. It counts from the last fork, not from
   * the original genesis (ADR 0007), and a lightnet has had no fork, so here the two are the same.
   */
  const clockSlot = async () => {
    const { data } = await graphql(endpoints.mina, 'Clock', 'query Clock { daemonStatus { consensusTimeNow { globalSlot } } }');
    return BigInt(data.daemonStatus.consensusTimeNow.globalSlot);
  };

  /** Sends `tx` and answers why it did not apply, or nothing if it did. */
  async function submit(tx: Tx, keys: PrivateKey[]): Promise<string | undefined> {
    const sent = await tx.sign([sender.key, ...keys]).safeSend();
    if (sent.status === 'rejected') return sent.errors.map(String).join('; ');
    const done = await sent.safeWait({ maxAttempts: 60, interval: 5_000 });
    return done.status === 'rejected' ? done.errors.map(String).join('; ') : undefined;
  }

  /** Lands a transaction whose slots `build` chooses, building it again whenever a block refuses it. */
  async function land(name: string, build: () => Promise<Tx>, keys: PrivateKey[] = []) {
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      await fetchAccount({ publicKey: sender });
      const failure = await submit(await build(), keys);
      if (failure === undefined) return log(`${name}: landed, attempt ${attempt}`);
      log(`${name}: refused, attempt ${attempt}: ${failure}`);
    }
    throw Error(`${name}: did not land in ${ATTEMPTS} attempts`);
  }

  /**
   * Lands a transaction that must land at the slot it names or the slot after. `build` proves it for the
   * slot it is given; the lead grows to what proving last took, plus a slot to reach the mempool.
   */
  async function landAt(name: string, build: (slot: bigint) => Promise<Tx>, lead: bigint) {
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      const slot = (await clockSlot()) + lead;
      await fetchAccount({ publicKey: sender });
      const started = Date.now();
      const tx = await build(slot);
      lead = BigInt(Math.ceil((Date.now() - started) / SLOT_MS)) + 2n;
      if ((await clockSlot()) >= slot) {
        log(`${name}: proving outlasted slot ${slot}, attempt ${attempt}; next, ${lead} slots ahead`);
        continue;
      }
      while ((await clockSlot()) < slot - 1n) await sleep(1_000);
      const failure = await submit(tx, []);
      if (failure === undefined) return log(`${name}: landed for slot ${slot}, attempt ${attempt}`);
      log(`${name}: missed slot ${slot}, attempt ${attempt}: ${failure}`);
    }
    throw Error(`${name}: did not land in ${ATTEMPTS} attempts`);
  }

  const zkappKey = PrivateKey.random();
  const stateKey = PrivateKey.random();
  const vault = new Vault(zkappKey.toPublicKey());
  batchReducer.setContractInstance(vault);

  /** Waits until the archive lists `count` of the vault's actions, and fetches its account. */
  async function archived(count: number) {
    for (let i = 0; i < 120; i++) {
      if ((await actions(vault.address)).length >= count) return fetchAccount({ publicKey: vault.address });
      await sleep(5_000);
    }
    throw Error(`the archive never listed ${count} of the vault's actions`);
  }

  /** Folds every action dispatched so far, of which there are `count`. They must fit one batch. */
  async function reduce(count: number) {
    await archived(count);
    const batches = await provableBatches();
    if (batches.length !== 1) throw Error(`expected one batch of actions, found ${batches.length}`);
    const [{ batch, proof }] = batches;
    await landAt('reduce', async (slot) => {
      await fetchAccount({ publicKey: vault.address });
      const mirror = await vaultView(vault);
      const reduced = (await actions(vault.address, vault.actionState.get())).length;
      (await actions(vault.address)).slice(reduced).forEach((a) => mirror.dispatched(a));
      const { witnesses, nullifiers, escapes } = mirror.nextReduce(slot);
      const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
        await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(slot));
      });
      await tx.prove();
      return tx;
    }, 12n);
  }

  /** Deposits a fresh note, named at the slot it lands in, and returns it. */
  async function deposit() {
    const secret = PrivateKey.random().toBigInt();
    const size = DEPOSIT_SIZES[0];
    let depositTime = 0n;
    await landAt('deposit', async (slot) => {
      depositTime = slot;
      await fetchAccount({ publicKey: vault.address });
      const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
        await vault.deposit(commitSecret(Field(secret)), UInt64.from(size), UInt64.from(slot));
      });
      await tx.prove();
      return tx;
    }, 6n);
    return { secret, size, depositTime };
  }

  log('compiling the circuits and the vault');
  await batchReducer.compile();
  await WithdrawalProgram.compile();
  await RequestProgram.compile();
  await Vault.compile();

  log(`deploying the vault at ${vault.address.toBase58()}`);
  await land('deploy', async () => {
    const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
      AccountUpdate.fundNewAccount(sender);
      await vault.deploy({ zkappUri: VAULT_URI });
    });
    await tx.prove();
    return tx;
  }, [zkappKey]);

  const signature = Signature.create(zkappKey, setupFields(vault.address, stateKey.toPublicKey(), sender));
  await land('setup', async () => {
    await fetchAccount({ publicKey: vault.address });
    const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
      await vault.setup(stateKey.toPublicKey(), sender, signature);
    });
    await tx.prove();
    return tx;
  });

  const spent = await deposit();
  const note = await deposit();
  await reduce(2);

  // The escape names its own window, which is wide: it may be proved at leisure.
  let consumedNullifier = Field(0);
  await fetchAccount({ publicKey: vault.address });
  const beforeEscape = await vaultView(vault);
  await land('escape', async () => {
    await fetchAccount({ publicKey: vault.address });
    const requestTime = await clockSlot();
    const { pub, priv } = buildWithdrawal(beforeEscape.tree, {
      kind: WithdrawalKind.escape, secret: spent.secret, index: beforeEscape.indexOf(commitSecret(Field(spent.secret))),
      size: spent.size, depositTime: spent.depositTime, requestTime, signed: false, balance: spent.size, blinding: 99n,
      stateKey, destination: sender, validUntil: requestTime + ESCAPE_VALIDITY_SLOTS,
    });
    consumedNullifier = pub.nullifier;
    const { proof } = await WithdrawalProgram.escape(pub, priv);
    const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
      await vault.escape(proof, beforeEscape.nullifiers.clone());
    });
    await tx.prove();
    return tx;
  });
  await reduce(3);

  // What the proofs are built over, read back from the chain as a payer would.
  await archived(3);
  const view = await vaultView(vault);

  const address = vault.address.toBase58();
  const readEvents = () => graphql(endpoints.archive, 'EscapeEvents',
    `query EscapeEvents($vault: String!) { events(input: { address: $vault }) {
      blockInfo { height chainStatus } eventData { data transactionInfo { hash status } } } }`, { vault: address });
  let escapeEvents = await readEvents();
  for (let i = 0; i < 120 && escapeEvents.data.events.length === 0; i++) {
    await sleep(5_000);
    escapeEvents = await readEvents();
  }
  if (escapeEvents.data.events.length === 0) throw Error('the archive never listed the escape event');

  const vaultState = await graphql(endpoints.mina, 'VaultState',
    `query VaultState($vault: PublicKey!) { account(publicKey: $vault) { zkappState actionState }
      bestChain(maxLength: 1) { protocolState { consensusState { slotSinceGenesis } } } }`, { vault: address });
  const recordedActions = await graphql(endpoints.archive, 'VaultActions',
    `query VaultActions($vault: String!) { actions(input: { address: $vault }) {
      blockInfo { height chainStatus } actionState { actionStateOne actionStateTwo }
      actionData { data transactionInfo { hash status } } } }`, { vault: address });

  return {
    recording: {
      about: 'Mina daemon and archive answers for a vault on the proofs-on lightnet: two reduced deposits, one of them escaped. Made by `npm run request-fixtures` in o1js/, with the request proofs beside this file. The unsubsidised proof is made at the tip slot recorded here; the subsidised one at a recorded deposit slot + 6720, which this chain had not reached (docs/verification-keys.md).',
      vault: address, vaultState, actions: recordedActions, escapeEvents,
    },
    tree: view.tree,
    index: view.indexOf(commitSecret(Field(note.secret))),
    note,
    stateKey,
    creationTime: vault.creationTime.get().toBigInt(),
    slot: BigInt(vaultState.data.bestChain[0].protocolState.consensusState.slotSinceGenesis),
    consumedNullifier,
  };
}
