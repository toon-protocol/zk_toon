import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Field, Mina, PrivateKey, fetchAccount } from 'o1js';
import { connectLightnet } from './lightnet.js';
import { OrderingProbe, deployProbe, onChain, writeThenRead } from './ordering-probe.js';

// #33 on a proofs-on lightnet: every account update's proof is checked by the chain.
const { sender, release } = await connectLightnet();

describe('preconditions within one zkApp command (proofs-on lightnet)', () => {
  const probeKey = PrivateKey.random();
  const probe = new OrderingProbe(probeKey.toPublicKey());
  /** The probe's on-chain state after the last block. */
  const refresh = async () => {
    await fetchAccount({ publicKey: probe.address });
    return onChain(probe);
  };

  beforeAll(async () => {
    expect(Mina.getProofsEnabled()).toBe(true);
    await deployProbe(probe, probeKey, sender);
  });
  afterAll(release);

  it('a later update sees the state an earlier update wrote', async () => {
    const before = await refresh();
    const result = await writeThenRead(probe, sender, Field(7), { x: 'new', actionState: 'new' });
    console.log('new x, new action state:', result);
    expect(result.status).toBe('included');
    const after = await refresh();
    expect(after.x).toBe(7n);
    expect(after.actionState).not.toBe(before.actionState);
  });

  it('a later update whose state precondition is on the old value is rejected', async () => {
    const before = await refresh();
    const result = await writeThenRead(probe, sender, Field(8), { x: 'old', actionState: 'new' });
    console.log('old x, new action state:', result);
    expect(result.status).toBe('rejected');
    expect(result.errors.join('\n')).toMatch(/Account_app_state_0_precondition_unsatisfied/);
    expect(await refresh()).toEqual(before);
  });

  // An action-state precondition passes if it matches any of the account's last five action states.
  // A dispatch in a later slot than the account's last one shifts that ring, so the state from before
  // `write` is still in it and the old-value precondition holds too. That is the ring, not the order:
  // the first test's new action state was in no ring entry before the command.
  it('an action-state precondition on the pre-command state also holds, from the ring', async () => {
    const before = await refresh();
    const result = await writeThenRead(probe, sender, Field(9), { x: 'new', actionState: 'old' });
    console.log('new x, old action state:', result);
    expect(result.status).toBe('included');
    await refresh();
    const ring = Mina.getAccount(probe.address).zkapp!.actionState.map((s) => s.toBigInt());
    expect(ring[0]).not.toBe(before.actionState);
    expect(ring[1]).toBe(before.actionState);
  });
});
