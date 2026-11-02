// What the devnet smoke run (`devnet-main.ts`) computes without touching a chain: the funder's key from its
// mnemonic, the run's own keys, and when to send a command. See `docs/devnet-smoke.md`.
import { createECDH, createHmac, pbkdf2Sync } from 'node:crypto';
import { PrivateKey, UInt64 } from 'o1js';
import { CHALLENGE_WINDOW_SLOTS, SLOT_SECONDS } from './policy.js';
import type { Vault } from './vault.js';

const SLOT_MS = Number(SLOT_SECONDS) * 1000;
/** The order of secp256k1's group, which BIP32 keys are scalars of. */
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HARDENED = 0x80000000;

export const bip39Seed = (mnemonic: string, passphrase = ''): Uint8Array =>
  pbkdf2Sync(mnemonic.normalize('NFKD'), `mnemonic${passphrase}`.normalize('NFKD'), 2048, 64, 'sha512');

const toBig = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).toString('hex')}`);
const to32 = (n: bigint) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');

/** The BIP32 secp256k1 private key at `path`, each step an index, hardened when at or above 2^31. */
export function bip32Derive(seed: Uint8Array, path: number[]): Uint8Array {
  const master = createHmac('sha512', 'Bitcoin seed').update(seed).digest();
  let key = master.subarray(0, 32);
  let chain = master.subarray(32);
  for (const step of path) {
    const index = Buffer.alloc(4);
    index.writeUInt32BE(step);
    const data = step >= HARDENED
      ? Buffer.concat([Buffer.alloc(1), key, index])
      : Buffer.concat([compressedKey(key), index]);
    const i = createHmac('sha512', chain).update(data).digest();
    key = to32((toBig(i.subarray(0, 32)) + toBig(key)) % SECP256K1_ORDER);
    chain = i.subarray(32);
  }
  return key;
}

function compressedKey(key: Uint8Array) {
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(key);
  return Buffer.from(ecdh.getPublicKey(null, 'compressed'));
}

/** The key of Mina's first account as Auro derives it: BIP44 coin 12586, top two bits cleared, big-endian. */
export function minaKeyFromMnemonic(mnemonic: string): PrivateKey {
  const path = [44 + HARDENED, 12586 + HARDENED, HARDENED, 0, 0];
  const key = Buffer.from(bip32Derive(bip39Seed(mnemonic), path));
  key[0]! &= 0x3f;
  return PrivateKey.fromBigInt(toBig(key));
}

/**
 * A secret of run `run` named `label`, derived from the funder's key so nothing need be written down: a
 * resumed run finds the same keys and notes. 250 bits, below both the field and the scalar modulus.
 */
export const runSecret = (funder: bigint, run: string, label: string): bigint =>
  toBig(createHmac('sha256', to32(funder)).update(`zk-toon/devnet-smoke/${run}/${label}`).digest()) & ((1n << 250n) - 1n);

export const runKey = (funder: bigint, run: string, label: string) => PrivateKey.fromBigInt(runSecret(funder, run, label));

/** The chain's latest block: its slot and when that slot began. */
export type Clock = { tipSlot: bigint; tipMs: number };

const slotStart = (c: Clock, slot: bigint) => c.tipMs + Number(slot - c.tipSlot) * SLOT_MS;

/** The first slot a command can be aimed at, if proving it takes `proveMs` from `nowMs`. */
export const targetSlot = (c: Clock, nowMs: number, proveMs: number) =>
  c.tipSlot + BigInt(Math.floor((nowMs + proveMs - c.tipMs) / SLOT_MS)) + 1n;

/**
 * What to do with a command whose slot range starts at `target` and ends a slot later, the vault's tightest
 * range. A block in an earlier slot would fail the command and still charge its fee, so it waits until the
 * block of the slot before its target has probably been made. From the start of the range's last slot, a
 * block is unlikely to carry it in time.
 */
export function sendPlan(c: Clock, nowMs: number, target: bigint): { kind: 'wait'; ms: number } | { kind: 'send' } | { kind: 'late' } {
  const from = slotStart(c, target - 1n) + SLOT_MS / 3;
  if (nowMs < from) return { kind: 'wait', ms: from - nowMs };
  return nowMs < slotStart(c, target + 1n) ? { kind: 'send' } : { kind: 'late' };
}

/**
 * The challenge window of a short-window test run: about 3 minutes instead of 2 days, so a devnet run can show
 * an escape paying out in one sitting. Only `npm run devnet -- short-<name> --short-window` uses it.
 */
export const SHORT_CHALLENGE_WINDOW_SLOTS = 2n;
const SHORT_RUN = /^short-/;

/**
 * The window run `run` is for. A short-window run says so twice, in its name and its flag, so neither its
 * journal nor a command line can pass for the other kind.
 */
export function windowOfRun(run: string, shortWindow: boolean): bigint {
  if (shortWindow !== SHORT_RUN.test(run)) {
    throw Error(`run ${run}: a run is named short-<name> exactly when it has --short-window`);
  }
  return shortWindow ? SHORT_CHALLENGE_WINDOW_SLOTS : CHALLENGE_WINDOW_SLOTS;
}

/**
 * Refuses a run whose window is not the one its journal recorded, or not the one its vault holds on chain.
 * `journalled` is the journal's window. A journal from before windows were recorded has none, and if it has
 * deployed (`deployed`) it deployed the published window. `onChain` is the vault's state, once it exists.
 */
export function refuseWindowMismatch(window: bigint, was: { journalled?: string; deployed: boolean; onChain?: bigint }) {
  const journalled = was.journalled !== undefined ? BigInt(was.journalled) : was.deployed ? CHALLENGE_WINDOW_SLOTS : undefined;
  if (journalled !== undefined && journalled !== window) {
    throw Error(`this run's challenge window is ${window} slots, but its journal's is ${journalled}`);
  }
  if (was.onChain !== undefined && was.onChain !== window) {
    throw Error(`this run's challenge window is ${window} slots, but its vault holds ${was.onChain}`);
  }
}

/**
 * Deploys `vault` with `window` as its challenge window, within a transaction. `init` isn't a proved method: it
 * runs inside the signed deploy, so the window is state the deployer writes, and the verification keys don't
 * depend on it. The published vault's `deploy` and keys never reach this code.
 */
export async function deployWithWindow(vault: Vault, zkappUri: string, window: bigint) {
  await vault.deploy({ zkappUri });
  vault.challengeWindow.set(UInt64.from(window));
}

/** What a run's journal says about its build, in words a reader can't miss. */
export function buildNotice(window: bigint, codeHash: string) {
  if (window === CHALLENGE_WINDOW_SLOTS) return `Published vault build: a challenge window of ${window} slots.`;
  return `SHORT-WINDOW TEST BUILD: its challenge window is ${window} slots, not the published ${CHALLENGE_WINDOW_SLOTS}. `
    + `Its window is state written at deploy, so its code hash ${codeHash} and key hashes (see facts) can't tell it from a vault with the published window.`;
}
