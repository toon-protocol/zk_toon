// What catches an o1js upgrade: zk-prover mirrors o1js's gadgets, and its witnesses are compared with
// frozen o1js fixtures. If a new o1js changes a gadget's constraints, the program it compiles changes,
// and this fails until the fixtures are regenerated and the Rust mirrors match (`zk-prover/src/pins.rs`).
// A change to witness values alone leaves the key as it is: only regenerating the fixtures shows that,
// which `tests/pins.rs` forces on a version bump.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { Land, PROGRAM_VK_HASH } from './land-program.js';
import { PROOFS_ON } from './proofs-on.js';

const inputs = JSON.parse(gunzipSync(readFileSync(new URL('../../zk-prover/fixtures/inputs.json.gz', import.meta.url))).toString());

describe('the program zk-prover proves', () => {
  it(PROOFS_ON.landVk, async () => {
    const { verificationKey } = await Land.compile();
    expect(verificationKey.hash.toString()).toBe(PROGRAM_VK_HASH);
    expect(inputs.vkHash).toBe(PROGRAM_VK_HASH);
    expect(verificationKey.data).toBe(inputs.vk);
  }, 1_800_000);
});
