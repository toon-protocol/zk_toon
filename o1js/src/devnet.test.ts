import { describe, expect, it } from 'vitest';
import { bip32Derive, bip39Seed, runKey, runSecret, sendPlan, targetSlot } from './devnet.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const SLOT_MS = 90_000;

describe('deriving the funder key', () => {
  it('turns a mnemonic into the BIP39 seed (published vector)', () => {
    const words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    expect(hex(bip39Seed(words, 'TREZOR'))).toBe(
      'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'
    );
  });

  it('walks hardened and normal BIP32 steps (published vector 1)', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    expect(hex(bip32Derive(seed, []))).toBe('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35');
    expect(hex(bip32Derive(seed, [0x80000000]))).toBe('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea');
    expect(hex(bip32Derive(seed, [0x80000000, 1]))).toBe('3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368');
  });
});

describe('a run\'s keys', () => {
  it('are the same on every resume, and differ by label and by run', () => {
    const funder = 123456789n;
    expect(runKey(funder, 'a', 'vault').toBase58()).toBe(runKey(funder, 'a', 'vault').toBase58());
    expect(runKey(funder, 'a', 'vault').toBase58()).not.toBe(runKey(funder, 'a', 'state').toBase58());
    expect(runKey(funder, 'a', 'vault').toBase58()).not.toBe(runKey(funder, 'b', 'vault').toBase58());
    expect(runSecret(funder, 'a', 'note')).not.toBe(runSecret(funder, 'b', 'note'));
  });
});

describe('aiming a command at a slot', () => {
  // The tip is slot 100, seen at the start of that slot.
  const clock = { tipSlot: 100n, tipMs: 1_000_000 };

  it('targets the slot after the proof is ready and the command has reached the pool', () => {
    // Proving ends 200 s in, during slot 102, so slot 103 is the first it can be sent ahead of.
    expect(targetSlot(clock, 1_000_000, 200_000)).toBe(103n);
  });

  it('counts from the wall clock, not a stale tip', () => {
    expect(targetSlot(clock, 1_000_000 + 5 * SLOT_MS, 0)).toBe(106n);
  });

  it('holds a command until a third into the slot before its target', () => {
    const sendAt = 1_000_000 + 2 * SLOT_MS + SLOT_MS / 3;
    expect(sendPlan(clock, 1_000_000, 102n + 1n)).toEqual({ kind: 'wait', ms: sendAt - 1_000_000 });
  });

  it('sends at once from then until the target slot has begun', () => {
    expect(sendPlan(clock, 1_000_000 + 2 * SLOT_MS + SLOT_MS / 2, 103n)).toEqual({ kind: 'send' });
    expect(sendPlan(clock, 1_000_000 + 3 * SLOT_MS + 1000, 103n)).toEqual({ kind: 'send' });
  });

  it('gives a proof up once it can only reach a block past the target\'s last slot', () => {
    expect(sendPlan(clock, 1_000_000 + 4 * SLOT_MS, 103n)).toEqual({ kind: 'late' });
  });
});
