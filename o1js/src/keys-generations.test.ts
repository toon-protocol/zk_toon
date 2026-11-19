// Vault generations (ADR 0015): one build compiles every generation in the policy's table, each with its own constants.
// The table here has a second generation that only this test adds.
import { describe, expect, it } from 'vitest';
import { buildKeys, currentKeys } from './keys.js';
import {
  GENERATIONS, CURRENT_GENERATION, CURRENT_GENERATION_ID, generationById, generationOf, generationOfCodeHash,
} from './policy.js';

const shorter = generationOf('test-45s', 45n);

describe('vault generations', () => {
  it('a second generation has its own vault, and the current generation keeps its keys', async () => {
    const alone = await buildKeys();
    const both = await buildKeys({ generations: [...GENERATIONS, shorter] });
    expect(Object.keys(both.generations)).toEqual([CURRENT_GENERATION_ID, shorter.id]);
    expect(both.current).toBe(CURRENT_GENERATION_ID);

    // The vault's code hash and the circuits' keys follow the slot counts.
    const extra = both.generations[shorter.id];
    const cur = currentKeys(both);
    expect(extra.vault.codeHash).not.toBe(cur.vault.codeHash);
    expect(extra.circuits.request.verificationKey.hash).not.toBe(cur.circuits.request.verificationKey.hash);
    expect(extra.circuits.withdrawal.verificationKey.hash).not.toBe(cur.circuits.withdrawal.verificationKey.hash);

    // Adding a generation changes nothing of the current one's, or the registry's, down to the byte.
    expect(JSON.stringify(both.generations[CURRENT_GENERATION_ID])).toBe(JSON.stringify(alone.generations[CURRENT_GENERATION_ID]));
    expect(JSON.stringify(both.registry)).toBe(JSON.stringify(alone.registry));

    // A code hash finds its generation; one in none is refused, naming it.
    expect(generationOfCodeHash(extra.vault.codeHash, both.generations, [...GENERATIONS, shorter])).toEqual(shorter);
    expect(generationOfCodeHash(cur.vault.codeHash, both.generations)).toEqual(CURRENT_GENERATION);
    expect(() => generationOfCodeHash('12345', both.generations)).toThrow('12345');
  }, 3_600_000);
});

describe('the generation table', () => {
  it('holds today\'s values as the current generation, found by id', () => {
    expect(GENERATIONS.map((g) => g.id)).toContain(CURRENT_GENERATION_ID);
    expect(generationById(CURRENT_GENERATION_ID)).toBe(CURRENT_GENERATION);
    expect(CURRENT_GENERATION).toMatchObject({
      slotSeconds: 90n, slotsPerDay: 960n, noteLifetimeSlots: 172_800n, minSubsidyAgeSlots: 6_720n,
      subsidyPeriodSlots: 6_720n, challengeWindowSlots: 1_920n, requestMaxAgeSlots: 7n, requestMaxLeadSlots: 1n,
    });
    expect(() => generationById('nope')).toThrow("no vault generation 'nope'");
  });

  it('rounds a generation\'s slot counts up as ADR 0007 does', () => {
    expect(shorter).toMatchObject({ slotsPerDay: 1_920n, requestMaxAgeSlots: 14n, requestMaxLeadSlots: 2n });
  });
});
