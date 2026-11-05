// Connects o1js to the proofs-on lightnet started by `lightnet/lightnet.sh up`, and lends a funded
// genesis account from its account manager, and lands commands on it (`lightnetLanding`). Shared by the lightnet tests
// (`*.lightnet.ts`) and `request-fixtures-main.ts`.
import { Lightnet, Mina, PrivateKey, fetchAccount } from 'o1js';

export const MINA = 'http://127.0.0.1:8080/graphql';
export const ARCHIVE = 'http://127.0.0.1:8282';
const ACCOUNT_MANAGER = 'http://127.0.0.1:8181';

/** Sets the lightnet as the active chain and acquires a funded sender; `release` gives it back. */
export async function connectLightnet() {
  Mina.setActiveInstance(
    Mina.Network({ networkId: 'testnet', mina: MINA, archive: ARCHIVE, lightnetAccountManager: ACCOUNT_MANAGER })
  );
  const { publicKey, privateKey } = await Lightnet.acquireKeyPair();
  return {
    sender: Mina.TestPublicKey(privateKey),
    release: () => Lightnet.releaseKeyPair({ publicKey: publicKey.toBase58() }),
  };
}

/** The lightnet's slot. */
const SLOT_MS = 20_000;
/** How many times a transaction is built again before it is given up. */
const ATTEMPTS = 12;
type Tx = Awaited<ReturnType<typeof Mina.transaction>>;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Sends and lands commands on the lightnet at `mina`, paid and signed by `sender`. A command that must land at the slot
 * it names or the slot after (a vault's deposit or reduce, a registry's `register`) names a slot far enough ahead to
 * prove in, waits for it, and is built again if it misses.
 */
export function lightnetLanding(mina: string, sender: Mina.TestPublicKey, log: (line: string) => void = console.log) {
  /**
   * The slot the daemon's clock is in, which may be past the tip's. It counts from the last fork, not from
   * the original genesis (ADR 0007), and a lightnet has had no fork, so here the two are the same.
   */
  async function clockSlot() {
    const response = await fetch(mina, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: '{ daemonStatus { consensusTimeNow { globalSlot } } }' }),
    });
    const body = await response.json();
    if (!body.data) throw Error(`daemonStatus: ${JSON.stringify(body.errors)}`);
    return BigInt(body.data.daemonStatus.consensusTimeNow.globalSlot);
  }

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
   * slot it is given; the lead grows to what proving last took, plus a slot to reach the mempool. Answers the slot.
   */
  async function landAt(name: string, build: (slot: bigint) => Promise<Tx>, lead: bigint, keys: PrivateKey[] = []) {
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
      const failure = await submit(tx, keys);
      if (failure === undefined) {
        log(`${name}: landed for slot ${slot}, attempt ${attempt}`);
        return slot;
      }
      log(`${name}: missed slot ${slot}, attempt ${attempt}: ${failure}`);
    }
    throw Error(`${name}: did not land in ${ATTEMPTS} attempts`);
  }

  return { clockSlot, submit, land, landAt };
}
