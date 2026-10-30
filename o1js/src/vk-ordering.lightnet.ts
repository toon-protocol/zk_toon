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
  const refresh = async () => {
    await fetchAccount({ publicKey: address });
    return cachedAccount(address);
  };

  beforeAll(async () => {
    expect(Mina.getProofsEnabled()).toBe(true);
    keys = await compileBoth();
    await deployV1(new VkProbeV1(address), zkappKey, sender);
  });
  afterAll(release);

  // C and B run first: both leave the account on V1, so A (which changes it) goes last.
  it('C: no key update, proof against V2: rejected', async () => {
    const before = await refresh();
    expect(before.vkHash).toBe(keys.v1.hash.toBigInt());
    const result = await setKeyThenResume(address, zkappKey, sender, undefined, 'v2');
    console.log('C (control):', result);
    expect(result.status).toBe('rejected');
    expect(await refresh()).toEqual(before);
  });

  it('B: key update to V2, proof against V1: rejected', async () => {
    const before = await refresh();
    const result = await setKeyThenResume(address, zkappKey, sender, keys.v2, 'v1');
    console.log('B:', result);
    expect(result.status).toBe('rejected');
    expect(await refresh()).toEqual(before);
  });

  it('A: key update to V2, proof against V2: applied', async () => {
    const result = await setKeyThenResume(address, zkappKey, sender, keys.v2, 'v2');
    console.log('A:', result);
    expect(result.status).toBe('included');
    expect(await refresh()).toEqual({ vkHash: keys.v2.hash.toBigInt(), x: V2_MARK });
  });
});
