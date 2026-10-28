import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Field } from 'o1js';
import { buildVectors } from './vectors.js';
import * as p from './primitives.js';
import * as policy from './policy.js';

const file = JSON.parse(
  readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8')
);

describe('shared vectors', () => {
  it('are reproduced by o1js', () => {
    expect(JSON.parse(JSON.stringify(buildVectors()))).toEqual(file);
  });

  it('give the same inputs different outputs under different domain tags', () => {
    const outs = Object.values(file.domainSeparation.outputs);
    expect(new Set(outs).size).toBe(outs.length);
    expect(outs.length).toBe(Object.keys(p.TAGS).length);
  });

  it('use distinct domain tags', () => {
    const fields = Object.values(file.tags).map((t: any) => t.field);
    expect(new Set(fields).size).toBe(fields.length);
  });

  it('give one note different per-period nullifiers in every period', () => {
    const same = file.periodNullifiers.filter((v: any) => v.secret === file.nullifiers.secret && v.index === '7');
    const outs = same.map((v: any) => v.periodNullifier);
    expect(new Set(outs).size).toBe(outs.length);
  });

  it('give another secret a different per-period nullifier for the same index and period', () => {
    const at = (secret: string) =>
      file.periodNullifiers.find((v: any) => v.secret === secret && v.index === '7' && v.period === '1');
    const other = file.periodNullifiers.find((v: any) => v.secret !== file.nullifiers.secret).secret;
    expect(at(file.nullifiers.secret).periodNullifier).not.toBe(at(other).periodNullifier);
  });

  it('classify tiers and deposit sizes', () => {
    expect(file.membership.length).toBeGreaterThan(0);
    for (const m of file.membership) {
      const amount = BigInt(m.amount);
      expect([policy.isTier(amount), policy.isDepositSize(amount), policy.isSmallestTier(amount)])
        .toEqual([m.isTier, m.isDepositSize, m.isSmallestTier]);
    }
  });

  it('derive the next anchor from the nullifier, which needs the secret', () => {
    const n = file.nullifiers;
    expect(n.chain[1].anchor).toBe(n.nextAnchors[0]);
    expect(p.nullifier(Field(987654321n), Field(n.chain[0].anchor)).toString()).not.toBe(n.chain[0].nullifier);
  });

  it('take the edge from the vault key the zk edge signs state under', () => {
    const vaultXs = file.stateSignatures.cases.map((c: any) => c.vault.x);
    for (const e of file.authTags) expect(vaultXs).toContain(e.context.edge);
    for (const r of file.requestProofs) expect(r.private.context.edge).toBe(r.public.vault.x);
  });

  it('accept a requestTime 10 minutes behind to 1 minute ahead', () => {
    const now = 1_700_000_000_000n;
    const min = policy.MS_PER_MINUTE;
    expect(policy.isRequestTimeFresh(now - 10n * min, now)).toBe(true);
    expect(policy.isRequestTimeFresh(now - 10n * min - 1n, now)).toBe(false);
    expect(policy.isRequestTimeFresh(now + min, now)).toBe(true);
    expect(policy.isRequestTimeFresh(now + min + 1n, now)).toBe(false);
  });

  it('agree at week boundaries', () => {
    const c = 1_690_000_000_000n;
    const w = policy.SUBSIDY_PERIOD_MS;
    expect(policy.subsidyPeriod(c, c - 1n)).toBeUndefined();
    expect(policy.subsidyPeriod(c, c + w - 1n)).toBe(0n);
    expect(policy.subsidyPeriod(c, c + w)).toBe(1n);
    expect(policy.subsidyPeriod(c, c + w + 1n)).toBe(1n);
  });
});
