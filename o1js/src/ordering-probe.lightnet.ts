import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Field, Mina, PrivateKey, fetchAccount } from 'o1js';
import { connectLightnet } from './lightnet.js';
import { OrderingProbe, deployProbe, cachedState, writeThenRead } from './ordering-probe.js';

// #33 on a proofs-on lightnet: every account update's proof is checked by the chain.
const { sender, release } = await connectLightnet();

describe('preconditions within one zkApp command (proofs-on lightnet)', () => {
  const probeKey = PrivateKey.random();
  const probe = new OrderingProbe(probeKey.toPublicKey());
  /** The probe's on-chain state after the last block. */
  const refresh = async () => {
    await fetchAccount({ publicKey: probe.address });
    return cachedState(probe);
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

  // The old action state is still one of the account's last five: `write` dispatches in a later slot than
  // the first test's dispatch (a block apart), which shifts them. See lightnet/README.md.
  it('an action-state precondition on the pre-command state also holds, from the last five', async () => {
    const before = await refresh();
    const result = await writeThenRead(probe, sender, Field(9), { x: 'new', actionState: 'old' });
    console.log('new x, old action state:', result);
    expect(result.status).toBe('included');
    const { actionStates } = await refresh();
    expect(actionStates[0]).not.toBe(before.actionState);
    expect(actionStates[1]).toBe(before.actionState);
  });

  it('an action-state precondition on a state the account never had is rejected', async () => {
    const before = await refresh();
    const result = await writeThenRead(probe, sender, Field(10), { x: 'new', actionState: Field(1) });
    console.log('new x, never-seen action state:', result);
    expect(result.status).toBe('rejected');
    expect(result.errors.join('\n')).toMatch(/Account_action_state_precondition_unsatisfied/);
    expect(await refresh()).toEqual(before);
  });
});
