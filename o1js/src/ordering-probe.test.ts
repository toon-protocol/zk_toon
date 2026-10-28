import { beforeAll, describe, expect, it } from 'vitest';
import { Field, Mina, PrivateKey } from 'o1js';
import { OrderingProbe, deployProbe, onChain, writeThenRead } from './ordering-probe.js';

// An early signal only (#33): proofs off, so the ledger logic runs but no circuit is checked.
// The proofs-on run is `npm run test:lightnet`.
const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);

describe('preconditions within one zkApp command (LocalBlockchain)', () => {
  const [sender] = Local.testAccounts;
  const probeKey = PrivateKey.random();
  const probe = new OrderingProbe(probeKey.toPublicKey());

  beforeAll(async () => {
    await deployProbe(probe, probeKey, sender);
  });

  it('a later update sees the state an earlier update wrote', async () => {
    const before = onChain(probe);
    const result = await writeThenRead(probe, sender, Field(7), { x: 'new', actionState: 'new' });
    expect(result.status).toBe('included');
    expect(onChain(probe).x).toBe(7n);
    expect(onChain(probe).actionState).not.toBe(before.actionState);
  });

  it('a later update whose state precondition is on the old value is rejected', async () => {
    const before = onChain(probe);
    const result = await writeThenRead(probe, sender, Field(8), { x: 'old', actionState: 'new' });
    expect(result.status).toBe('rejected');
    expect(result.errors.join('\n')).toMatch(/app_state_precondition_unsatisfied/i);
    expect(onChain(probe)).toEqual(before);
  });

  // LocalBlockchain never advances the slot, so a dispatch overwrites the newest entry of the account's
  // five-state action-state ring instead of shifting it, and the old state leaves the ring. On a chain
  // whose slot has moved on, the old state stays in the ring and the precondition holds (the lightnet test).
  it('in the slot of the last dispatch, an action-state precondition on the old state is rejected', async () => {
    const before = onChain(probe);
    const result = await writeThenRead(probe, sender, Field(9), { x: 'new', actionState: 'old' });
    expect(result.status).toBe('rejected');
    expect(result.errors.join('\n')).toMatch(/action_state_precondition_unsatisfied/i);
    expect(onChain(probe)).toEqual(before);
  });
});
