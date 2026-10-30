// A throwaway zkApp for #35: does Mina check an account update's proof against a verification key that an
// earlier account update in the same zkApp command installed? Two circuits, V1 and V2, share one address
// and one state layout. V1 is deployed. One command holds a signed update that sets V2's key, then a call
// to `resume` on V1 or V2, which carries a proof of that circuit and writes its own marker into `x`.
import {
  AccountUpdate, Bool, Field, Mina, PrivateKey, PublicKey, SmartContract, State, declareMethods, declareState,
} from 'o1js';
import { submit, type Outcome } from './ordering-probe.js';

export class VkProbeV1 extends SmartContract {
  x = State<Field>();
  async resume() {
    this.x.set(Field(1));
  }
}
declareMethods(VkProbeV1, { resume: [] } as Record<string, any[]>);
declareState(VkProbeV1, { x: Field });

export class VkProbeV2 extends SmartContract {
  x = State<Field>();
  async resume() {
    this.x.set(Field(2));
  }
}
declareMethods(VkProbeV2, { resume: [] } as Record<string, any[]>);
declareState(VkProbeV2, { x: Field });

/** `x` after V1's and V2's `resume`. */
export const V1_MARK = 1n;
export const V2_MARK = 2n;

const FEE = 100_000_000;

export type Key = { data: string; hash: Field };
export type { Outcome };

/** Compiles both circuits and returns their verification keys, which differ. */
export async function compileBoth(): Promise<{ v1: Key; v2: Key }> {
  const v1 = (await VkProbeV1.compile()).verificationKey;
  const v2 = (await VkProbeV2.compile()).verificationKey;
  if (v1.hash.equals(v2.hash).toBoolean()) throw Error('V1 and V2 have the same verification key');
  return { v1, v2 };
}

/** Deploys the zkApp with V1 and the default permissions: `setVerificationKey` is `signature`. */
export async function deployV1(zkapp: VkProbeV1, zkappKey: PrivateKey, sender: Mina.TestPublicKey) {
  const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
    AccountUpdate.fundNewAccount(sender);
    await zkapp.deploy();
  });
  const outcome = await submit(tx, [sender.key, zkappKey]);
  if (outcome.status !== 'included') throw Error(`deploy failed: ${outcome.errors.join('; ')}`);
}

/** The account's verification-key hash and `x`, as o1js last saw them: on a network, `fetchAccount` first. */
export function cachedAccount(address: PublicKey) {
  const account = Mina.getAccount(address);
  return { vkHash: account.zkapp!.verificationKey!.hash.toBigInt(), x: account.zkapp!.appState[0].toBigInt() };
}

/**
 * One command with two account updates on the zkApp: a signed one that sets `newKey` (if given), then a
 * call to `resume` of `circuit`, proved against it.
 */
export async function setKeyThenResume(
  address: PublicKey,
  zkappKey: PrivateKey,
  sender: Mina.TestPublicKey,
  newKey: Key | undefined,
  circuit: 'v1' | 'v2'
): Promise<Outcome> {
  const app = circuit === 'v1' ? new VkProbeV1(address) : new VkProbeV2(address);
  const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
    if (newKey) {
      const update = AccountUpdate.createSigned(address);
      update.body.update.verificationKey = { isSome: Bool(true), value: newKey };
    }
    await app.resume();
  });
  return submit(tx, [sender.key, zkappKey]);
}
