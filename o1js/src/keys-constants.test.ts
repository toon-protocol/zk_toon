// A file of its own, so a process of its own: compiling again after keys.test.ts's real proof crashes
// or hangs V8 ("Check failed: !root_map_->is_deprecated()"), and a hang outlives the test's timeout.
import { describe, expect, it } from 'vitest';
import { Cache, Mina, UInt64 } from 'o1js';
import { buildKeys } from './keys.js';
import { PROOFS_ON } from './proofs-on.js';

describe('the keys do not depend on the network', () => {
  it(PROOFS_ON.constants, async () => {
    const keys = await buildKeys();
    // A chain whose genesis and slot length differ from o1js's defaults (ADR 0007): any `network.*` time
    // precondition would compile to other slot ranges and so to other keys.
    const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
    const constants = { ...Local.getNetworkConstants(), genesisTimestamp: UInt64.from(1_717_171_717_000n), slotTime: UInt64.from(90_000n) };
    expect(constants.slotTime.toBigInt()).not.toBe(Local.getNetworkConstants().slotTime.toBigInt());
    expect(constants.genesisTimestamp.toBigInt()).not.toBe(Local.getNetworkConstants().genesisTimestamp.toBigInt());
    Mina.setActiveInstance({ ...Local, getNetworkConstants: () => constants });
    const other = await buildKeys({ cache: Cache.None });
    expect(other).toEqual(keys);
  }, 1_800_000);
});
