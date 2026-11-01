import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Mina, PrivateKey, fetchAccount } from 'o1js';
import { connectLightnet } from './lightnet.js';
import {
  V2_MARK, VkProbeV1, cachedAccount, compileBoth, deployV1, setKeyThenResume, type Key,
} from './vk-ordering.js';

// #35 on a proofs-on lightnet: does a proof get checked against the key an earlier update installed?
const { sender, release } = await connectLightnet();

describe('verification key ordering within one zkApp command (proofs-on lightnet)', () => {
  const zkappKey = PrivateKey.random();
  const address = zkappKey.toPublicKey();
  let keys: { v1: Key; v2: Key };
  /** The zkApp's on-chain key hash and state after the last block. */
  const onChain = async () => {
    await fetchAccount({ publicKey: address });
    return cachedAccount(address);
  };

  beforeAll(async () => {
    expect(Mina.getProofsEnabled()).toBe(true);
    keys = await compileBoth();
    await deployV1(new VkProbeV1(address), zkappKey, sender);
  });
  afterAll(release);

  // The cases are those of #35. C and B run first: both leave the account on V1, so A, which changes it,
  // goes last and these tests depend on running in file order.
  it('C: no key update, proof against V2: rejected', async () => {
    const before = await onChain();
    expect(before.vkHash).toBe(keys.v1.hash.toBigInt());
    const result = await setKeyThenResume(zkappKey, sender, 'v2');
    console.log('C (control):', result);
    expect(result.status).toBe('rejected');
    expect(result.rejectedAt).toBe('safeSend');
    expect(result.errors.join('\n')).toMatch(/Invalid_proof \(Pickles.verify dlog_check\)/);
    expect(await onChain()).toEqual(before);
  });

  it('B: key update to V2, proof against V1: rejected', async () => {
    const before = await onChain();
    const result = await setKeyThenResume(zkappKey, sender, 'v1', keys.v2);
    console.log('B:', result);
    expect(result.status).toBe('rejected');
    expect(result.rejectedAt).toBe('safeSend');
    expect(result.errors.join('\n')).toMatch(/Invalid_proof \(Pickles.verify dlog_check\)/);
    expect(await onChain()).toEqual(before);
  });

  it('A: key update to V2, proof against V2: applied', async () => {
    const result = await setKeyThenResume(zkappKey, sender, 'v2', keys.v2);
    console.log('A:', result);
    expect(result.status).toBe('included');
    expect(await onChain()).toEqual({ vkHash: keys.v2.hash.toBigInt(), x: V2_MARK });
  });
});
