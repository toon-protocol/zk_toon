// The transaction builder: builds and proves vault transactions and request proofs for callers in
// other languages (the wallet and the challenger, in Rust). Requests and answers are JSON objects;
// `tx-builder-main.ts` carries them as newline-delimited JSON over stdin and stdout, and
// `docs/tx-builder.md` documents them.
//
// Secrets (a note's secret, its state's blinding, a re-randomising blinding, the fee payer's private
// key) arrive only in a request. The builder keeps them in memory for that request, never logs them,
// never writes them to disk, and scrubs them from any failure message it answers with.
import { AccountUpdate, Bool, Field, Mina, PrivateKey, PublicKey, Scalar, Signature, UInt64, fetchAccount, verify } from 'o1js';
import { commit, rerandomise } from './balance.js';
import { authTag, commitSecret, genesisAnchor, nextAnchor, nullifier } from './primitives.js';
import { RequestPrivate, RequestProgram, RequestProof, RequestPublic, subsidyPeriodHolds } from './request.js';
import { expiryOf } from './policy.js';
import { PendingEscape, PendingEscapes, VAULT_URI, Vault, batchReducer, setupFields } from './vault.js';
import { VaultKeeper, chainNow, escapeEvents, pendingEscapesView, vaultView } from './vault-view.js';
import type { VaultMirror } from './vault-mirror.js';
import { WithdrawalKind, WithdrawalPrivate, WithdrawalProgram, WithdrawalPublic } from './withdrawal.js';

/** The kinds of failure answer. */
export type FailureKind = 'badInput' | 'provingFailed' | 'chainUnavailable' | 'rejected';

export class Failure extends Error {
  constructor(readonly kind: FailureKind, message: string) {
    super(message);
  }
}

export interface BuilderOptions {
  /** Host an o1js LocalBlockchain (proofs off) and answer the `local.*` operations. */
  local: boolean;
  /** Make real proofs; otherwise the ZkProgram proofs are dummies. */
  proofs: boolean;
  /** Mina GraphQL and archive endpoints, when not local. */
  mina?: string;
  archive?: string;
}

type Params = Record<string, unknown>;
type Op = (p: Params, secrets: string[]) => Promise<unknown>;

// --- Reading the interface's encodings. A malformed value is a `badInput` failure. ---

const bad = (message: string) => new Failure('badInput', message);

function obj(v: unknown, name: string): Params {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw bad(`${name}: expected an object`);
  return v as Params;
}
function decimal(v: unknown, name: string): bigint {
  if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw bad(`${name}: expected a decimal string`);
  return BigInt(v);
}
function u64(v: unknown, name: string): bigint {
  const n = decimal(v, name);
  if (n >= 1n << 64n) throw bad(`${name}: does not fit in 64 bits`);
  return n;
}
function field(v: unknown, name: string): Field {
  const n = decimal(v, name);
  if (n >= Field.ORDER) throw bad(`${name}: not below the field modulus`);
  return Field(n);
}
function publicKey(v: unknown, name: string): PublicKey {
  try {
    return PublicKey.fromBase58(v as string);
  } catch {
    throw bad(`${name}: expected a base58 public key`);
  }
}
function privateKey(v: unknown, name: string, secrets: string[]): PrivateKey {
  if (typeof v === 'string') secrets.push(v);
  try {
    return PrivateKey.fromBase58(v as string);
  } catch {
    throw bad(`${name}: expected a base58 private key`);
  }
}
/** A secret decimal: recorded for scrubbing before it is read. */
function secretDecimal(v: unknown, name: string, secrets: string[]): bigint {
  if (typeof v === 'string') secrets.push(v);
  const n = decimal(v, name);
  secrets.push(n.toString());
  return n;
}
function scalar(n: bigint, name: string): Scalar {
  if (n >= Scalar.ORDER) throw bad(`${name}: not below the scalar modulus`);
  return Scalar.from(n);
}
function signature(v: unknown, name: string): Signature {
  const p = obj(v, name);
  return Signature.fromValue({ r: field(p.r, `${name}.r`), s: scalar(decimal(p.s, `${name}.s`), `${name}.s`) });
}

/** What the payer keeps about its deposit. */
function note(v: unknown, secrets: string[]) {
  const p = obj(v, 'note');
  const secret = secretDecimal(p.secret, 'note.secret', secrets);
  if (secret >= Field.ORDER) throw bad('note.secret: not below the field modulus');
  return { secret: Field(secret), size: u64(p.size, 'note.size'), depositTime: u64(p.depositTime, 'note.depositTime') };
}
type Note = ReturnType<typeof note>;

/** The note's current state: genesis, or a signed state whose anchor follows from the previous state's. */
function noteState(v: unknown, n: Note, secrets: string[]) {
  const p = obj(v, 'state');
  const blinding = scalar(secretDecimal(p.blinding, 'state.blinding', secrets), 'state.blinding');
  const genesis = genesisAnchor(commitSecret(n.secret));
  if (p.signed === null || p.signed === undefined) {
    return {
      balance: n.size, blinding, anchor: genesis, isGenesis: Bool(true), prevNullifier: Field(0), prevAnchor: Field(0),
      // Unchecked for a genesis state; any signature fills the slot.
      signature: Signature.create(PrivateKey.fromBigInt(1n), [Field(0)]),
    };
  }
  const signed = obj(p.signed, 'state.signed');
  const prevAnchor = field(signed.prevAnchor, 'state.signed.prevAnchor');
  const prevNullifier = nullifier(n.secret, prevAnchor);
  return {
    balance: u64(signed.balance, 'state.signed.balance'), blinding, anchor: nextAnchor(prevNullifier),
    isGenesis: Bool(false), prevNullifier, prevAnchor, signature: signature(signed.signature, 'state.signed.signature'),
  };
}
type NoteState = ReturnType<typeof noteState>;

/** The note's index in the vault's tree. */
function indexOf(view: VaultMirror, n: Note): bigint {
  try {
    return view.indexOf(commitSecret(n.secret));
  } catch {
    throw bad('note: the vault holds no reduced note with this secret');
  }
}

const fieldStrings = (fields: Field[]) => fields.map((f) => f.toString());

function feePayer(v: unknown, secrets: string[]) {
  const p = obj(v, 'feePayer');
  const key = privateKey(p.privateKey, 'feePayer.privateKey', secrets);
  return { key, sender: key.toPublicKey(), fee: UInt64.from(u64(p.fee ?? '0', 'feePayer.fee')) };
}

/** Runs `build`; anything it throws that is not already a failure is a proving failure. */
async function proving<T>(build: () => Promise<T>): Promise<T> {
  try {
    return await build();
  } catch (e) {
    if (e instanceof Failure) throw e;
    throw new Failure('provingFailed', e instanceof Error ? e.message : String(e));
  }
}

/** Replaces every secret of the request in `message`. */
function scrub(message: string, secrets: string[]) {
  return secrets.filter((s) => s.length > 0).reduce((m, s) => m.split(s).join('[redacted]'), message);
}

export async function createBuilder(options: BuilderOptions) {
  let local: Awaited<ReturnType<typeof Mina.LocalBlockchain>> | undefined;
  if (options.local) {
    local = await Mina.LocalBlockchain({ proofsEnabled: false });
    Mina.setActiveInstance(local);
  } else {
    Mina.setActiveInstance(Mina.Network({ mina: options.mina ?? '', archive: options.archive }));
  }
  const keeper = new VaultKeeper();
  let reducerCompiled = false;
  WithdrawalProgram.setProofsEnabled(options.proofs);
  RequestProgram.setProofsEnabled(options.proofs);
  let requestVk: Awaited<ReturnType<typeof RequestProgram.compile>>['verificationKey'] | undefined;
  let withdrawalCompiled = false;
  let vaultCompiled = false;

  /** Compiles what proving needs, once: a request or withdrawal proof, and a vault transaction when the chain checks proofs. */
  async function compile(o: { request?: boolean; withdrawal?: boolean; vault?: boolean }) {
    if (o.request && options.proofs && !requestVk) requestVk = (await RequestProgram.compile()).verificationKey;
    if (o.withdrawal && options.proofs && !withdrawalCompiled) {
      await WithdrawalProgram.compile();
      withdrawalCompiled = true;
    }
    if (o.vault && Mina.getProofsEnabled() && !vaultCompiled) {
      await batchReducer.compile();
      if (!withdrawalCompiled) await WithdrawalProgram.compile();
      // The vault's defeat and raise verify request proofs.
      if (!requestVk) requestVk = (await RequestProgram.compile()).verificationKey;
      await Vault.compile();
      vaultCompiled = withdrawalCompiled = reducerCompiled = true;
    }
  }

  /** The vault at `address`, with its accounts fetched when the chain is remote. */
  async function loadVault(address: unknown, others: PublicKey[] = []) {
    const vault = new Vault(publicKey(address, 'vault'));
    if (!options.local) {
      for (const publicKey of [vault.address, ...others]) {
        const { error } = await fetchAccount({ publicKey });
        if (error) throw new Failure('chainUnavailable', `could not fetch account ${publicKey.toBase58()}: ${error.statusText}`);
      }
    }
    batchReducer.setContractInstance(vault);
    return vault;
  }

  async function view(vault: Vault) {
    try {
      return await vaultView(vault);
    } catch (e) {
      throw new Failure('chainUnavailable', e instanceof Error ? e.message : String(e));
    }
  }

  /** The vault's pending escapes, rebuilt from its `escape` events and checked against its root. */
  async function pendingEscapes(vault: Vault) {
    try {
      return await pendingEscapesView(vault, { localChain: options.local });
    } catch (e) {
      throw new Failure('chainUnavailable', e instanceof Error ? e.message : String(e));
    }
  }

  /**
   * A defeat or raise of the escape pending at `p.escape`, with `p.evidence` (a request proof's
   * `JsonProof`) as its evidence. Answers the transaction and its hash.
   */
  async function challenge(
    p: Params, secrets: string[],
    call: (vault: Vault, escape: PendingEscape, evidence: RequestProof, escapes: PendingEscapes) => Promise<void>
  ) {
    const payer = feePayer(p.feePayer, secrets);
    const vault = await loadVault(p.vault, [payer.sender]);
    const at = field(p.escape, 'escape');
    let evidence: RequestProof;
    try {
      evidence = await RequestProof.fromJSON(obj(p.evidence, 'evidence') as never);
    } catch {
      throw bad('evidence: not a request proof');
    }
    const { escapes, records } = await pendingEscapes(vault);
    const escape = records.get(at.toBigInt());
    if (!escape) throw bad('escape: the vault holds no pending escape at this nullifier');
    const zkappCommand = await transaction(payer, () => call(vault, escape, evidence, escapes.clone()));
    return { zkappCommand, hash: await Mina.Transaction.hash(zkappCommand) };
  }

  /** A withdrawal proof of `kind` for the request's note and state. */
  async function withdrawal(kind: WithdrawalKind, p: Params, vault: Vault, secrets: string[], escape?: { conceded: bigint; validUntil: bigint }) {
    const n = note(p.note, secrets);
    const s = noteState(p.state, n, secrets);
    const requestTime = u64(p.requestTime, 'requestTime');
    const destination = publicKey(p.destination, 'destination');
    const mirror = await view(vault);
    const index = indexOf(mirror, n);
    const current = nullifier(n.secret, s.anchor);
    const pub = new WithdrawalPublic({
      kind: Field(kind), vault: vault.stateKey.get(), root: mirror.tree.root, nullifier: current,
      nextNullifier: escape ? nullifier(n.secret, nextAnchor(current)) : Field(0),
      amount: Field(s.balance), size: Field(n.size), destination,
      validUntil: Field(escape?.validUntil ?? 0n), requestTime: Field(requestTime), conceded: Field(escape?.conceded ?? 0n),
    });
    const priv = new WithdrawalPrivate({
      secret: n.secret, index: Field(index), depositTime: Field(n.depositTime), expiry: Field(expiryOf(n.depositTime)),
      path: mirror.tree.witness(index), blinding: s.blinding, anchor: s.anchor, isGenesis: s.isGenesis,
      signature: s.signature, prevNullifier: s.prevNullifier, prevAnchor: s.prevAnchor,
    });
    const method = kind === WithdrawalKind.escape ? WithdrawalProgram.escape : WithdrawalProgram.mutualClose;
    const proof = await proving(async () => {
      await compile({ withdrawal: true });
      return (await method(pub, priv)).proof;
    });
    return { proof, mirror, publicInputFields: fieldStrings(WithdrawalPublic.toFields(pub)) };
  }

  /** A signed, proved transaction from `feePayer`, as Mina GraphQL's `sendZkapp` takes it. */
  async function transaction(payer: ReturnType<typeof feePayer>, body: () => Promise<void>) {
    const tx = await proving(async () => {
      await compile({ vault: true });
      const tx = await Mina.transaction({ sender: payer.sender, fee: payer.fee }, body);
      await tx.prove();
      return tx;
    });
    tx.sign([payer.key]);
    return JSON.parse(tx.toJSON());
  }

  const ops: Record<string, Op> = {
    async deposit(p, secrets) {
      const payer = feePayer(p.feePayer, secrets);
      const vault = await loadVault(p.vault, [payer.sender]);
      const commitment = field(p.commitment, 'commitment');
      const size = UInt64.from(u64(p.size, 'size'));
      const depositTime = UInt64.from(u64(p.depositTime, 'depositTime'));
      const zkappCommand = await transaction(payer, async () => {
        await vault.deposit(commitment, size, depositTime);
      });
      return { zkappCommand };
    },
    async mutualClose(p, secrets) {
      const payer = feePayer(p.feePayer, secrets);
      const vault = await loadVault(p.vault, [payer.sender]);
      const clearance = signature(p.clearance, 'clearance');
      const { proof, mirror, publicInputFields } = await withdrawal(WithdrawalKind.mutualClose, p, vault, secrets);
      const zkappCommand = await transaction(payer, async () => {
        await vault.mutualClose(proof, clearance, mirror.nullifiers.clone());
      });
      return { zkappCommand, publicInputFields };
    },
    async escape(p, secrets) {
      const payer = feePayer(p.feePayer, secrets);
      const vault = await loadVault(p.vault, [payer.sender]);
      const escape = { conceded: u64(p.conceded, 'conceded'), validUntil: u64(p.validUntil, 'validUntil') };
      const { proof, mirror, publicInputFields } = await withdrawal(WithdrawalKind.escape, p, vault, secrets, escape);
      const zkappCommand = await transaction(payer, async () => {
        await vault.escape(proof, mirror.nullifiers.clone());
      });
      return { zkappCommand, publicInputFields };
    },
  };

  ops.defeat = (p, secrets) =>
    challenge(p, secrets, async (vault, escape, evidence, escapes) => {
      await vault.defeat(escape, evidence, escapes);
    });
  ops.raise = (p, secrets) => {
    const claimed = UInt64.from(u64(p.claimed, 'claimed'));
    return challenge(p, secrets, async (vault, escape, evidence, escapes) => {
      await vault.raise(escape, evidence, claimed, escapes);
    });
  };

  /** The unsubsidised request proof, with the vault's state key as the zk edge. */
  ops.requestProof = async (p, secrets) => {
    const vault = await loadVault(p.vault);
    const n = note(p.note, secrets);
    const s = noteState(p.state, n, secrets);
    const rerandom = scalar(secretDecimal(p.rerandomBlinding, 'rerandomBlinding', secrets), 'rerandomBlinding');
    const requestTime = u64(p.requestTime, 'requestTime');
    const tier = u64(p.tier, 'tier');
    const session = publicKey(p.sessionKey, 'sessionKey');
    const requestExpiry = u64(p.requestExpiry, 'requestExpiry');
    const mirror = await view(vault);
    const index = indexOf(mirror, n);

    const stateKey = vault.stateKey.get();
    const current = nullifier(n.secret, s.anchor);
    const context = {
      edge: stateKey.x, sessionKeyX: session.x, sessionKeyIsOdd: session.isOdd, tier: Field(tier), expiry: Field(requestExpiry),
    };
    const pub = new RequestPublic({
      vault: stateKey, root: mirror.tree.root, requestTime: Field(requestTime), tier: Field(tier), nullifier: current,
      tag: authTag(current, context), commitment: rerandomise(commit(Scalar.from(s.balance), s.blinding), rerandom),
      subsidised: Bool(false), period: Field(0), periodNullifier: Field(0),
    });
    const priv = new RequestPrivate({
      secret: n.secret, index: Field(index), size: Field(n.size), depositTime: Field(n.depositTime),
      expiry: Field(expiryOf(n.depositTime)), path: mirror.tree.witness(index), balance: Field(s.balance),
      blinding: s.blinding, rerandomBlinding: rerandom, anchor: s.anchor, isGenesis: s.isGenesis, signature: s.signature,
      prevNullifier: s.prevNullifier, prevAnchor: s.prevAnchor, edge: context.edge, sessionKeyX: context.sessionKeyX,
      sessionKeyIsOdd: context.sessionKeyIsOdd, requestExpiry: context.expiry,
    });
    const proof = await proving(async () => {
      await compile({ request: true });
      return (await RequestProgram.unsubsidised(pub, priv)).proof;
    });
    return { publicInputFields: fieldStrings(RequestPublic.toFields(pub)), proof: proof.toJSON() };
  };

  /**
   * Whether a request proof verifies against the request program's verification key and, given the
   * vault's `vaultCreation`, whether its period is that vault's (`subsidyPeriodHolds`).
   */
  ops.verifyRequestProof = async (p) => {
    let proof: RequestProof;
    try {
      proof = await RequestProof.fromJSON(obj(p.proof, 'proof') as never);
    } catch {
      throw bad('proof: not a request proof');
    }
    const vaultCreation = p.vaultCreation === undefined ? undefined : u64(p.vaultCreation, 'vaultCreation');
    if (!options.proofs) throw bad('verifyRequestProof needs --proofs=on');
    await compile({ request: true });
    const periodHolds = vaultCreation === undefined || subsidyPeriodHolds(proof.publicInput, vaultCreation);
    return { valid: periodHolds && (await verify(proof, requestVk!)) };
  };

  /** Hashes of the commands `local.graphql` has landed. */
  const landed: string[] = [];
  const localOps: Record<string, Op> = {
    async 'local.accounts'() {
      return {
        accounts: local!.testAccounts.map((a) => ({ publicKey: a.toBase58(), privateKey: a.key.toBase58() })),
      };
    },
    async 'local.deployVault'(p) {
      const stateKey = publicKey(p.stateKey, 'stateKey');
      const treasury = publicKey(p.treasury, 'treasury');
      const [deployer] = local!.testAccounts;
      const zkappKey = PrivateKey.random();
      const vault = new Vault(zkappKey.toPublicKey());
      batchReducer.setContractInstance(vault);
      const deploy = await Mina.transaction(deployer, async () => {
        AccountUpdate.fundNewAccount(deployer);
        await vault.deploy({ zkappUri: VAULT_URI });
      });
      await deploy.prove();
      await deploy.sign([deployer.key, zkappKey]).send();
      const signature = Signature.create(zkappKey, setupFields(vault.address, stateKey, treasury));
      const setup = await Mina.transaction(deployer, async () => {
        await vault.setup(stateKey, treasury, signature);
      });
      await setup.prove();
      await setup.sign([deployer.key]).send();
      keeper.track(vault.address);
      return { vault: vault.address.toBase58() };
    },
    async 'local.submit'(p) {
      try {
        await Mina.Transaction.fromJSON(obj(p.zkappCommand, 'zkappCommand') as never).send();
      } catch (e) {
        throw new Failure('rejected', e instanceof Error ? e.message : String(e));
      }
      return {};
    },
    async 'local.reduce'(p) {
      if (!reducerCompiled) {
        await batchReducer.compile();
        reducerCompiled = true;
      }
      const [keeperAccount] = local!.testAccounts;
      await keeper.reduce(new Vault(publicKey(p.vault, 'vault')), keeperAccount);
      return {};
    },
    async 'local.advance'(p) {
      const slot = Mina.getNetworkConstants().slotTime.toBigInt();
      local!.incrementGlobalSlot(Number((u64(p.ms, 'ms') + slot - 1n) / slot));
      return {};
    },
    async 'local.now'() {
      return { now: chainNow().toString() };
    },
    async 'local.balance'(p) {
      return { balance: Mina.getBalance(publicKey(p.publicKey, 'publicKey')).toBigInt().toString() };
    },
    /**
     * The challenger adapter's GraphQL operations, answered from the local chain in the shapes the Mina
     * daemon and the archive node API answer them (`challenger-mina/src/graphql.rs`). Every command sent
     * lands at once, in a block of its own.
     */
    async 'local.graphql'(p) {
      const request = obj(p.request, 'request');
      const variables = obj(request.variables ?? {}, 'request.variables');
      const time = { protocolState: { blockchainState: { utcDate: chainNow().toString() } } };
      switch (`${p.endpoint}:${request.operationName}`) {
        case 'mina:VaultState': {
          const vault = publicKey(variables.vault, 'vault');
          const zkappState = Mina.getAccount(vault).zkapp!.appState.map((f) => f.toString());
          return { data: { account: { zkappState }, bestChain: [time] } };
        }
        case 'archive:EscapeEvents': {
          const vault = new Vault(publicKey(variables.vault, 'vault'));
          const { events } = await escapeEvents(vault, { localChain: true });
          return {
            data: {
              events: events.map((e, i) => ({
                blockInfo: { height: Number(e.height), chainStatus: 'canonical' },
                eventData: [{ data: e.data, transactionInfo: { hash: `local-${i}`, status: 'applied' } }],
              })),
            },
          };
        }
        case 'mina:SendChallenge': {
          const command = obj(obj(variables.input, 'input').zkappCommand, 'zkappCommand');
          try {
            await Mina.Transaction.fromJSON(command as never).send();
          } catch (e) {
            return { errors: [{ message: e instanceof Error ? e.message : String(e) }] };
          }
          const hash = await Mina.Transaction.hash(command as never);
          landed.push(hash);
          return { data: { sendZkapp: { zkapp: { hash } } } };
        }
        case 'mina:ChallengeStatus': {
          const zkappCommands = landed.map((hash) => ({ hash, failureReason: null }));
          return { data: { bestChain: [{ transactions: { zkappCommands }, ...time }], pooledZkappCommands: [] } };
        }
        default:
          throw bad(`local.graphql: no ${String(request.operationName)} on ${String(p.endpoint)}`);
      }
    },
    async 'local.vaultState'(p) {
      const vault = new Vault(publicKey(p.vault, 'vault'));
      return {
        noteRoot: vault.noteRoot.get().toString(),
        nextLeafIndex: vault.nextLeafIndex.get().toString(),
        nullifierRoot: vault.nullifierRoot.get().toString(),
        pendingEscapesRoot: vault.pendingEscapesRoot.get().toString(),
        stateKey: vault.stateKey.get().toBase58(),
        treasury: vault.treasury.get().toBase58(),
        creationTime: vault.creationTime.get().toString(),
      };
    },
  };

  const table: Record<string, Op> = options.local ? { ...ops, ...localOps } : ops;

  /** Answers one request line with one answer line. Never throws. */
  async function handle(line: string): Promise<string> {
    let id: unknown = null;
    const secrets: string[] = [];
    try {
      let request: Params;
      try {
        request = obj(JSON.parse(line), 'request');
      } catch (e) {
        throw e instanceof Failure ? e : bad('not a JSON request');
      }
      id = request.id ?? null;
      const op = table[request.op as string];
      if (typeof request.op !== 'string' || !Object.hasOwn(table, request.op) || !op) {
        throw bad(`unknown op: ${String(request.op)}`);
      }
      const result = await op(obj(request.params ?? {}, 'params'), secrets);
      return JSON.stringify({ id, ok: true, result });
    } catch (e) {
      const failure = e instanceof Failure ? e : new Failure('provingFailed', e instanceof Error ? e.message : String(e));
      return JSON.stringify({ id, ok: false, error: { kind: failure.kind, message: scrub(failure.message, secrets) } });
    }
  }

  return { handle };
}
