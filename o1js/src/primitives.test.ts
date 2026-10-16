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

  it('derive the next anchor from the nullifier, which needs the secret', () => {
    const n = file.nullifiers;
    expect(n.chain[1].anchor).toBe(n.nextAnchors[0]);
    expect(p.nullifier(Field(987654321n), Field(n.chain[0].anchor)).toString()).not.toBe(n.chain[0].nullifier);
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
