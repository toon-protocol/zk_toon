// The check a client runs before trusting a vault (ADR 0008). The vault code hash names only the code: `init`
// and `deploy` run under the vault account's signature, outside the circuit, so a deployer can start an account
// with the right hash and any state, permissions and actions. `checkVault` reads an address and answers with a
// pass, or a refusal naming what failed. Nothing it reads is trusted: an archive's actions are hashed up to the
// account's action state, and its events only supply deadlines that the pending escapes root then has to confirm.
//
// The vault must be one the pinned vault registry lists (ADR 0011): a vault deployed under its own key can be given a
// fake history before the account is locked, which replaying can't show. The registry is judged too: its key, its
// permissions, and its entries, hashed up to its action state.
//
// `judgeVault` is the check itself, a pure function of a snapshot; `test-vectors/vault-check.json` holds snapshots
// and their answers.
import { AccountUpdate, Experimental, Field, Mina, Permissions, PublicKey, Struct, TokenId, Types, UInt64, fetchAccount, fetchLastBlock } from 'o1js';
import { NoteTree } from './note-tree.js';
import * as policy from './policy.js';
import {
  ActionKind, CLOSE_WINDOW_SLOTS, DepositSizes, EscapeUpdate, NullifierSet, PendingEscapes, RootRing, VaultAction, VaultState,
} from './vault.js';

/** Every permission's value in ADR 0006's table, in o1js's JSON. `setVerificationKey` adds the transaction version. */
const PERMISSIONS: Record<string, string> = {
  editState: 'Proof',
  send: 'Proof',
  editActionState: 'Proof',
  access: 'None',
  receive: 'None',
  setVerificationKey: 'Impossible',
  setPermissions: 'Impossible',
  setTiming: 'Impossible',
  incrementNonce: 'Impossible',
  setZkappUri: 'Impossible',
  setVotingFor: 'Impossible',
  setTokenSymbol: 'Impossible',
  setDelegate: 'Signature',
};


/** What a verdict depends on of the registry, as JSON. `actions` is as in `VaultSnapshot`; each holds the fields of an address. */
export type RegistrySnapshot = {
  verificationKeyHash: string | null;
  permissions: Record<string, unknown>;
  timed: boolean;
  /** The account's latest action state. */
  actionState: string;
  actions: string[][][];
};

/** What the check is pinned to: the vault's and the registry's code hashes, as published. The registry's address is the reader's to read. */
export type VaultPins = { codeHash: string; registryCodeHash: string };

/** All a verdict depends on, as JSON. `actions` holds one list per account update, oldest update first, as o1js reads them. */
export type VaultSnapshot = {
  /** The vault's address, in base58. */
  address: string;
  registry: RegistrySnapshot;
  slot: string;
  verificationKeyHash: string | null;
  permissions: Record<string, unknown>;
  timed: boolean;
  balance: string;
  /** The account's latest action state. */
  actionState: string;
  appState: string[];
  treasuryExists: boolean;
  /** Who the actions name as a payee and has no account. */
  payeesWithoutAccount: string[];
  actions: string[][][];
  /** The fields of each `escape` event, in any order. */
  escapeEvents: string[][];
};

/** What a check depends on the chain for. A method that can't answer throws, and the check refuses. */
export type VaultReader = {
  /** The chain's current slot. */
  slot(): Promise<bigint>;
  /** The account as the node has it, or undefined if there is none. */
  account(address: PublicKey): Promise<Types.Account | undefined>;
  /** Every action the account dispatched, one list per account update, oldest first. */
  actions(address: PublicKey): Promise<string[][][]>;
  /** The fields of each of the account's events. */
  events(address: PublicKey): Promise<string[][]>;
};

type Refuse = (check: string, detail: string) => void;
/** The one thing that failed: `check` names it, `detail` says how. */
export type VaultRefusal = { check: string; detail: string };
/** `dispatched` is how many actions the vault's history holds. */
export type VaultVerdict = { pass: true; dispatched: number; reduced: number } | { pass: false; refusals: VaultRefusal[] };

/** Reads the active Mina instance. On a network it fetches first; `localChain` is for o1js's LocalBlockchain. */
export function chainReader({ localChain }: { localChain: boolean }): VaultReader {
  return {
    async slot() {
      if (!localChain) await fetchLastBlock();
      return Mina.getNetworkState().globalSlotSinceGenesis.toBigint();
    },
    async account(address) {
      if (localChain) return Mina.hasAccount(address) ? Mina.getAccount(address) : undefined;
      const { account, error } = await fetchAccount({ publicKey: address });
      if (error && !/not found|does not exist/i.test(error.statusText)) throw Error(error.statusText);
      return account;
    },
    async actions(address) {
      const lists = await Mina.fetchActions(address);
      if ('error' in lists) throw Error(JSON.stringify(lists.error));
      return lists.map((l) => l.actions);
    },
    async events(address) {
      const blocks = await Mina.fetchEvents(address, TokenId.default);
      // LocalBlockchain reverses its stored list on every read; a second read puts it back (`escapeEvents`).
      if (localChain) await Mina.fetchEvents(address, TokenId.default);
      return blocks.flatMap((b) => b.events.map((e) => e.data as string[]));
    },
  };
}

/** Reads what a verdict depends on. Throws if the reader does, or if there's no account at `address`. */
export async function readVault(address: PublicKey, registry: PublicKey, reader: VaultReader): Promise<VaultSnapshot> {
  const [account, registryAccount, registryActions] = await Promise.all([reader.account(address), reader.account(registry), reader.actions(registry)]);
  if (!registryAccount?.zkapp) throw Error(`no registry zkApp at ${registry.toBase58()}`);
  if (!account) throw Error(`no account at ${address.toBase58()}`);
  const json = Types.Account.toJSON(account);
  if (!account.zkapp) throw Error(`${address.toBase58()} is not a zkApp account`);
  const appState = account.zkapp.appState;
  const { treasury } = VaultState.fromFields(appState.slice(0, VaultState.sizeInFields()));
  const [slot, actions, events, treasuryAccount] = await Promise.all([
    reader.slot(), reader.actions(address), reader.events(address),
    treasury.isEmpty().toBoolean() ? undefined : reader.account(treasury),
  ]);
  const payees = namedPayees(actions);
  const found = await Promise.all(payees.map((p) => reader.account(p)));
  return {
    address: address.toBase58(),
    registry: {
      verificationKeyHash: registryAccount.zkapp.verificationKey?.hash.toString() ?? null,
      permissions: Types.Account.toJSON(registryAccount).permissions,
      timed: registryAccount.timing.isTimed.toBoolean(),
      actionState: registryAccount.zkapp.actionState[0]!.toString(),
      actions: registryActions,
    },
    slot: slot.toString(),
    verificationKeyHash: account.zkapp.verificationKey?.hash.toString() ?? null,
    permissions: json.permissions,
    timed: account.timing.isTimed.toBoolean(),
    balance: account.balance.toBigInt().toString(),
    actionState: account.zkapp.actionState[0]!.toString(),
    appState: appState.map((f) => f.toString()),
    treasuryExists: treasuryAccount !== undefined,
    payeesWithoutAccount: payees.filter((_, i) => !found[i]).map((p) => p.toBase58()),
    actions,
    escapeEvents: events,
  };
}

/** Everyone a close, an escape or what follows one names, once each. Actions that don't parse are `judgeVault`'s to refuse. */
function namedPayees(actions: string[][][]): PublicKey[] {
  try {
    const named = actions.flat().map((l) => VaultAction.fromFields(l.map((f) => Field(f))))
      .filter((a) => !a.kind.equals(ActionKind.deposit).toBoolean() && !a.kind.equals(ActionKind.sweep).toBoolean())
      .map((a) => a.destination);
    return [...new Map(named.map((p) => [p.toBase58(), p])).values()];
  } catch {
    return [];
  }
}

/** Asks one question of `address`: can it be trusted as a vault of `codeHash`, listed by `registry`? A failed read refuses. */
export async function checkVault(
  address: PublicKey, { codeHash, registry, registryCodeHash, reader }: VaultPins & { registry: PublicKey; reader: VaultReader }
): Promise<VaultVerdict> {
  let snapshot: VaultSnapshot;
  try {
    snapshot = await readVault(address, registry, reader);
  } catch (e) {
    return { pass: false, refusals: [{ check: 'read', detail: e instanceof Error ? e.message : String(e) }] };
  }
  return judgeVault(snapshot, { codeHash, registryCodeHash });
}

/** The verdict on a snapshot, against the published `codeHash` and this build's policy. */
export function judgeVault(s: VaultSnapshot, pins: VaultPins): VaultVerdict {
  try {
    return judge(s, pins);
  } catch (e) {
    // A snapshot that doesn't even parse came from a node or an archive answering wrongly.
    return { pass: false, refusals: [{ check: 'snapshot', detail: e instanceof Error ? e.message : String(e) }] };
  }
}

function judge(s: VaultSnapshot, { codeHash, registryCodeHash }: VaultPins): VaultVerdict {
  const refusals: VaultRefusal[] = [];
  const refuse = (check: string, detail: string) => refusals.push({ check, detail });
  const same = sameAs(refuse, 'expected');

  judgeRegistry(s, registryCodeHash, refuse);
  same('codeHash', s.verificationKeyHash ?? 'none', codeHash);
  judgePermissions('permissions', s.permissions, refuse);
  if (s.timed) refuse('timing', 'the account has a vesting schedule, which can lock deposits');

  const state = VaultState.fromFields(s.appState.slice(0, VaultState.sizeInFields()).map((f) => Field(f)));
  const sizes = DepositSizes.fromPolicy();
  same('depositSizes.a', state.depositSizes.a, sizes.a);
  same('depositSizes.b', state.depositSizes.b, sizes.b);
  same('depositSizes.c', state.depositSizes.c, sizes.c);
  same('noteLifetime', state.noteLifetime, policy.NOTE_LIFETIME_SLOTS);
  same('challengeWindow', state.challengeWindow, policy.CHALLENGE_WINDOW_SLOTS);
  if (state.creationTime.toBigInt() > BigInt(s.slot)) refuse('creationTime', `${state.creationTime} is after the current slot ${s.slot}`);
  if (state.stateKey.isEmpty().toBoolean()) refuse('setup', 'no state key: setup has not run');
  if (state.treasury.isEmpty().toBoolean()) refuse('setup', 'no treasury: setup has not run');
  else if (!s.treasuryExists) refuse('setup', 'the treasury has no account, so a reduce paying it would fail');
  // A payout to no account fails the reduce, and stalls every action behind it. The vault's methods require the account.
  for (const p of s.payeesWithoutAccount) refuse('payee', `${p} is named by an action and has no account`);

  const history = replayHistory(s, state, refuse);
  if (refusals.length > 0 || !history) return { pass: false, refusals };
  return { pass: true, ...history };
}

function judgePermissions(prefix: string, permissions: Record<string, unknown>, refuse: Refuse) {
  for (const [name, want] of Object.entries(permissionsWanted())) {
    const got = JSON.stringify(permissions[name]);
    if (got !== JSON.stringify(want)) refuse(`${prefix}.${name}`, `is ${got}, expected ${JSON.stringify(want)}`);
  }
}

/**
 * The registry is judged like a vault's account, and its entries are hashed up to its action state, since an archive's
 * answer counts only if they are. The vault must be among them. A fork replaces the registry, so one pin is judged.
 */
function judgeRegistry(s: VaultSnapshot, registryCodeHash: string, refuse: Refuse) {
  const r = s.registry;
  sameAs(refuse, 'expected')('registry.codeHash', r.verificationKeyHash ?? 'none', registryCodeHash);
  judgePermissions('registry.permissions', r.permissions, refuse);
  if (r.timed) refuse('registry.timing', 'the registry has a vesting schedule');
  const state = extendActionState(Experimental.BatchReducer.initialActionState, r.actions);
  if (state.toString() !== r.actionState) {
    refuse('registry.actionState', "the archive's registry entries do not hash to the registry's action state");
    return;
  }
  const listed = r.actions.flat().filter((e) => e.length === 2).map((e) => PublicKey.fromFields(e.map((f) => Field(f))).toBase58());
  if (!listed.includes(s.address)) refuse('registry', `${s.address} is not listed by the registry`);
}

/** `state` extended by each list of actions in `lists`, in order, as the chain extends an account's action state. */
export const extendActionState = (state: Field, lists: string[][][]) =>
  lists.reduce((acc, l) => AccountUpdate.Actions.updateSequenceState(acc, AccountUpdate.Actions.fromJSON(l).hash), state);

const sameAs = (refuse: Refuse, wanted: string) => (check: string, got: { toString(): string }, want: { toString(): string }) => {
  if (got.toString() !== want.toString()) refuse(check, `is ${got}, ${wanted} ${want}`);
};

/** ADR 0006's table as this build's o1js writes it: the verification key's permission names the transaction version. */
function permissionsWanted(): Record<string, unknown> {
  const { txnVersion } = Permissions.VerificationKey.impossibleDuringCurrentVersion();
  return { ...PERMISSIONS, setVerificationKey: { auth: PERMISSIONS.setVerificationKey, txnVersion: txnVersion.toString() } };
}

/**
 * Replays the vault's whole action stream from the empty tree, as its reduce would, and compares what that builds
 * with the account. Refuses and returns undefined if the stream isn't the account's, or can't be replayed.
 */
function replayHistory(s: VaultSnapshot, state: VaultState, refuse: Refuse) {
  const empty = Experimental.BatchReducer.initialActionState;
  // The archive's answer counts only if it hashes up to the action state on the account.
  const listHashes = s.actions.map((l) => AccountUpdate.Actions.fromJSON(l).hash);
  const statesAfter = listHashes.reduce<Field[]>(
    (acc, h) => [...acc, AccountUpdate.Actions.updateSequenceState(acc.at(-1) ?? empty, h)], []
  );
  if ((statesAfter.at(-1) ?? empty).toString() !== s.actionState) {
    refuse('actionState', "the archive's actions do not hash to the account's action state");
    return undefined;
  }

  // The vault's `actionState` is how far its reduces have got, always at the end of some list.
  const reducedLists = state.actionState.equals(empty).toBoolean()
    ? 0
    : statesAfter.findIndex((a) => a.equals(state.actionState).toBoolean()) + 1;
  if (reducedLists === 0 && !state.actionState.equals(empty).toBoolean()) {
    refuse('actionState', "the vault's reduced action state is not in its action history");
    return undefined;
  }

  // An action stack holds the actions between the reduced state and some later one, oldest on top. One that
  // doesn't would let a reduce pop actions never dispatched.
  const stacks = new Set([empty.toString()]);
  for (let end = reducedLists + 1; end <= listHashes.length; end++) {
    let stack = empty;
    for (let i = end - 1; i >= reducedLists; i--) stack = AccountUpdate.Actions.updateSequenceState(stack, listHashes[i]!);
    stacks.add(stack.toString());
  }
  if (!stacks.has(state.actionStack.toString())) refuse('actionStack', "the vault's action stack is not of its pending actions");

  const deadlines = new Map<bigint, bigint>();
  for (const data of s.escapeEvents) {
    const { pending, record } = EscapeUpdate.fromFields(data.map((f) => Field(f)));
    if (pending.toBoolean()) deadlines.set(record.nullifier.toBigInt(), record.deadline.toBigInt());
  }

  let actions: VaultAction[][];
  try {
    // Each method dispatches once. A longer list can stall the reduce: it can't pop more than a batch from one update.
    actions = s.actions.map((l) => {
      if (l.length !== 1) throw Error(`an account update holds ${l.length} actions`);
      return [decodeAction(l[0]!)];
    });
  } catch (e) {
    refuse('actions', (e as Error).message);
    return undefined;
  }

  const tree = new NoteTree();
  const nullifiers = new NullifierSet();
  const escapes = new PendingEscapes();
  const spent = new Set<bigint>();
  /** Hash of each escape still pending, by nullifier. A pending action's escape has no deadline yet, so no hash. */
  const standing = new Map<bigint, bigint | undefined>();
  const noteRoots = new Set<string>();
  const notes: { size: bigint; depositTime: bigint }[] = [];
  const depositedBySize = new Map<bigint, bigint>();
  const claimedBySize = new Map<bigint, bigint>();
  const add = (m: Map<bigint, bigint>, k: bigint, by: bigint) => m.set(k, (m.get(k) ?? 0n) + by);
  let [deposited, paid, claimed, swept, expired, cursor] = [0n, 0n, 0n, 0n, 0n, 0n];
  const lapse = policy.NOTE_LIFETIME_SLOTS + CLOSE_WINDOW_SLOTS;
  const paidBySize = new Map<bigint, bigint>();
  /** A close or finalize pays a note's size, and a note is deposited before it pays, so no size pays out more often. */
  const pays = (size: bigint) => {
    add(paidBySize, size, 1n);
    if (paidBySize.get(size)! > (depositedBySize.get(size) ?? 0n)) {
      throw Error(`action ${index} pays out more notes of size ${size} than were deposited before it`);
    }
  };
  const reducedCount = actions.slice(0, reducedLists).flat().length;
  let reduced = { paid: 0n, claimed: 0n, swept: 0n };
  let index = 0;

  const apply = (a: VaultAction, isReduced: boolean) => {
    const kind = Number(a.kind.toBigInt());
    const [size, nullifier, next] = [a.size.toBigInt(), a.nullifier.toBigInt(), a.nextNullifier.toBigInt()];
    if (kind === ActionKind.deposit) {
      deposited += size;
      add(depositedBySize, size, 1n);
      notes.push({ size, depositTime: a.time.toBigInt() });
      if (isReduced) {
        tree.append({ commitment: a.commitment, size: a.size.value, depositTime: a.time.value });
        noteRoots.add(tree.root.toString());
      }
    } else if (kind === ActionKind.mutualClose) {
      if (spent.has(nullifier)) return;
      spent.add(nullifier);
      if (isReduced) nullifiers.insert(a.nullifier, 1n);
      claimed += size;
      add(claimedBySize, size, 1n);
      pays(size);
      if (isReduced) paid += size;
    } else if (kind === ActionKind.escape) {
      // A note precedes its escape. Stale escapes may outnumber a note's deposit for a while (see the end of the replay).
      if (!depositedBySize.has(size)) throw Error(`action ${index} escapes a note of size ${size} before any was deposited`);
      if (spent.has(nullifier) || spent.has(next) || nullifier === next) return;
      spent.add(nullifier);
      spent.add(next);
      claimed += size;
      add(claimedBySize, size, 1n);
      if (!isReduced) {
        standing.set(nullifier, undefined);
        return;
      }
      nullifiers.insert(a.nullifier, 1n);
      nullifiers.insert(a.nextNullifier, 1n);
      const deadline = deadlines.get(nullifier);
      if (deadline === undefined) throw Error(`no escape event gives the deadline of the escape at ${nullifier}`);
      const hash = a.pendingEscape(UInt64.from(deadline)).hash();
      escapes.set(a.nullifier, hash);
      standing.set(nullifier, hash.toBigInt());
    } else if (kind === ActionKind.finalize || kind === ActionKind.defeat || kind === ActionKind.raise) {
      // Each is dispatched against a recorded escape, so an escape still unreduced can't be named yet.
      if (standing.has(nullifier) && standing.get(nullifier) === undefined) {
        throw Error(`action ${index} names an escape no reduce has recorded`);
      }
      const record = a.pendingEscape(a.time).hash();
      const named = kind === ActionKind.raise ? a.commitment.toBigInt() : record.toBigInt();
      if (standing.get(nullifier) !== named) return;
      if (kind === ActionKind.raise) {
        standing.set(nullifier, record.toBigInt());
        if (isReduced) escapes.set(a.nullifier, record);
        return;
      }
      standing.delete(nullifier);
      if (isReduced) escapes.set(a.nullifier, 0n);
      if (kind === ActionKind.defeat) {
        claimed -= size;
        add(claimedBySize, size, -1n);
      } else {
        pays(size);
        if (isReduced) paid += size;
      }
    } else if (kind === ActionKind.sweep) {
      // A sweep's total is the sizes of the notes it has walked, in index order, each already past its lapse.
      if (size < expired) throw Error(`a sweep of ${size} is below the expired total ${expired} before it`);
      let [total, walked] = [0n, 0n];
      for (const n of notes) {
        if (total >= size) break;
        if (n.depositTime + lapse > BigInt(s.slot)) throw Error(`a sweep of ${size} counts a note that has not expired`);
        total += n.size;
        walked++;
      }
      if (total !== size) throw Error(`a sweep of ${size} does not end at a note`);
      [expired, cursor] = [size, walked];
      if (isReduced) {
        const owed = claimed + swept;
        const left = size > owed ? size - owed : 0n;
        swept += left;
        paid += left;
      }
    }
  };

  try {
    for (const a of actions.flat()) {
      if (index === reducedCount) reduced = { paid, claimed, swept };
      apply(a, index < reducedCount);
      index++;
    }
    if (index === reducedCount) reduced = { paid, claimed, swept };
  } catch (e) {
    refuse('actions', (e as Error).message);
    return undefined;
  }

  // Judged only now: a stale escape can push these over until it is defeated, and a defeat gives its claim back.
  for (const [size, count] of claimedBySize) {
    if (count > (depositedBySize.get(size) ?? 0n)) refuse('claims', `${count} notes of size ${size} are claimed, more than were deposited`);
  }

  const same = sameAs(refuse, 'but replaying the actions gives');
  same('noteRoot', state.noteRoot, tree.root);
  same('nextLeafIndex', state.nextLeafIndex, tree.nextIndex);
  same('nullifierRoot', state.nullifierRoot, nullifiers.root);
  same('pendingEscapesRoot', state.pendingEscapesRoot, escapes.root);
  same('claimedTotal', state.claimedTotal, reduced.claimed);
  same('sweptTotal', state.sweptTotal, reduced.swept);
  same('expiredTotal', state.expiredTotal, expired);
  same('sweepCursor', state.sweepCursor, cursor);
  checkRing(state.rootRing, state.noteRoot, noteRoots, refuse);

  // Every deposit brought its size in when dispatched; only a reduce pays any out.
  const owed = deposited - reduced.paid;
  if (BigInt(s.balance) < owed) refuse('balance', `holds ${s.balance}, but the actions say it should hold at least ${owed}`);

  return { dispatched: actions.flat().length, reduced: reducedCount };
}

/** Each root in the ring was once the note root, so holds no note that wasn't deposited; the newest is the current one. */
function checkRing(ring: RootRing, noteRoot: Field, noteRoots: Set<string>, refuse: Refuse) {
  const roots = ring.roots.map((r) => r.toString());
  const stray = roots.find((r) => r !== '0' && !noteRoots.has(r));
  if (stray) {
    refuse('rootRing', `holds ${stray}, which was never the note root`);
    return;
  }
  const head = Number(ring.head.toBigInt());
  const newest = roots[(head + roots.length - 1) % roots.length];
  if (ring.head.toBigInt() >= BigInt(roots.length)) refuse('rootRing', `its head is ${ring.head}`);
  else if (noteRoots.size === 0 ? roots.some((r) => r !== '0') || head !== 0 : newest !== noteRoot.toString()) {
    refuse('rootRing', 'its newest root is not the note root');
  }
}

const UINT64_END = 1n << 64n;

const NAMING: (keyof VaultAction)[] = ['nullifier', 'nextNullifier', 'amount', 'conceded', 'size', 'destination', 'time'];
const CLOSING: (keyof VaultAction)[] = ['nullifier', 'amount', 'size', 'time', 'destination'];
/** The fields each kind's constructor sets on top of `VaultAction.none()`. */
const FIELDS_SET: Record<number, (keyof VaultAction)[]> = {
  [ActionKind.deposit]: ['commitment', 'size', 'time'],
  [ActionKind.mutualClose]: CLOSING,
  [ActionKind.escape]: [...CLOSING, 'nextNullifier', 'validUntil', 'conceded'],
  [ActionKind.finalize]: NAMING,
  [ActionKind.defeat]: NAMING,
  [ActionKind.raise]: [...NAMING, 'commitment'],
  [ActionKind.sweep]: ['size'],
};

/** An action as the vault could have dispatched it; anything else can only have been forged. */
function decodeAction(fields: string[]): VaultAction {
  if (fields.length !== VaultAction.sizeInFields()) throw Error(`an action has ${fields.length} fields`);
  const a = new VaultAction(VaultAction.fromFields(fields.map((f) => Field(f))));
  const [amount, size, time, validUntil, conceded] = [a.amount, a.size, a.time, a.validUntil, a.conceded].map((u) => u.toBigInt());
  if ([amount, size, time, validUntil, conceded].some((u) => u! >= UINT64_END)) throw Error('an action holds an amount or time over 64 bits');
  if (a.destination.isOdd.toField().toBigInt() > 1n) throw Error('an action has a malformed destination');
  const kind = Number(a.kind.toBigInt());
  if (!(kind in ActionKind)) throw Error(`an action has kind ${a.kind}`);
  const set = Object.fromEntries(FIELDS_SET[kind]!.map((name) => [name, a[name]]));
  const bare = VaultAction.toFields(new VaultAction({ ...VaultAction.none(), kind: a.kind, ...set }));
  if (VaultAction.toFields(a).some((f, i) => !f.equals(bare[i]!).toBoolean())) throw Error(`an action of kind ${a.kind} sets a field its kind leaves empty`);
  if (kind === ActionKind.sweep) return a;
  // A raise names the record it replaces by hash. Zero is what an unset key holds, so it would raise nothing into an escape.
  if (kind === ActionKind.raise && a.commitment.equals(0).toBoolean()) throw Error('a raise names no record');
  if (!policy.isDepositSize(size!)) throw Error(`an action names ${size}, not a deposit size`);
  // The reduce's circuit is one for all kinds, so these fail its range checks whatever the kind.
  if (conceded! > amount! || amount! > size!) throw Error('an action has amounts out of order');
  // A nullifier is a hash, so 0 can only be forged.
  if (kind !== ActionKind.deposit && a.nullifier.equals(0).toBoolean()) throw Error('an action has nullifier 0');
  if (kind === ActionKind.escape && a.nextNullifier.equals(0).toBoolean()) throw Error('an escape has next nullifier 0');
  return a;
}
