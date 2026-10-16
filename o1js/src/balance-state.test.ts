import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Field, Group, Provable, PublicKey, Scalar, Signature } from 'o1js';
import * as bal from './balance.js';
import { verifyState, type StateMessage } from './state.js';

const file = JSON.parse(
  readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8')
);

const pt = (j: { x: string; y: string }) => Group.from(BigInt(j.x), BigInt(j.y));
const sc = (n: string) => Scalar.from(BigInt(n));
const same = (a: Group, b: Group) => expect([a.x.toString(), a.y.toString()]).toEqual([b.x.toString(), b.y.toString()]);

describe('generators', () => {
  const { g, h, curveGenerator } = file.generators;

  it('are reproduced from the seed', () => {
    same(bal.deriveGenerator(0).point, pt(g));
    same(bal.deriveGenerator(1).point, pt(h));
    expect(bal.deriveGenerator(0).counter.toString()).toBe(g.counter);
    expect(bal.deriveGenerator(1).counter.toString()).toBe(h.counter);
  });

  it('are distinct from each other and from the curve generator', () => {
    const xs = [g.x, h.x, curveGenerator.x];
    expect(new Set(xs).size).toBe(3);
    same(Group.generator, pt(curveGenerator));
  });
});

describe('balance commitments', () => {
  it('are reproduced', () => {
    expect(file.balanceCommitments.length).toBeGreaterThan(0);
    for (const c of file.balanceCommitments) same(bal.commit(sc(c.balance), sc(c.blinding)), pt(c.commitment));
  });

  it('re-randomise to a commitment with blinding r + r\'', () => {
    expect(file.rerandomised.length).toBeGreaterThan(0);
    for (const v of file.rerandomised) {
      const c = bal.commit(sc(v.balance), sc(v.blinding));
      same(bal.rerandomise(c, sc(v.extra)), pt(v.rerandomised));
      same(pt(v.rerandomised), pt(v.recommitted));
    }
  });

  it('charge to a commitment of the lower balance without opening', () => {
    expect(file.charged.length).toBeGreaterThan(0);
    for (const v of file.charged) {
      const c = bal.commit(sc(v.balance), sc(v.blinding));
      same(bal.charge(c, sc(v.delta)), pt(v.charged));
      same(pt(v.charged), pt(v.recommitted));
    }
  });

  it('commit, re-randomise and charge inside a circuit', async () => {
    const out: Group[] = [];
    await Provable.runAndCheck(() => {
      const w = (n: string) => Provable.witness(Scalar, () => sc(n));
      const keep = (g: Group) => Provable.asProver(() => { out.push(Group.fromJSON(g.toJSON())); });
      for (const v of file.rerandomised) keep(bal.rerandomise(bal.commit(w(v.balance), w(v.blinding)), w(v.extra)));
      for (const v of file.charged) keep(bal.charge(bal.commit(w(v.balance), w(v.blinding)), w(v.delta)));
    });
    const expected = [...file.rerandomised.map((v: any) => v.rerandomised), ...file.charged.map((v: any) => v.charged)];
    expect(out.length).toBe(expected.length);
    out.forEach((g, i) => same(g, pt(expected[i])));
  });
});

describe('state signatures', () => {
  const message = (c: any): StateMessage => ({
    vault: PublicKey.fromGroup(Group.generator.scale(sc(c.secret))),
    commitment: pt(c.commitment),
    anchor: Field(c.anchor),
  });
  const sig = (c: any) => Signature.fromObject({ r: Field(c.signature.r), s: sc(c.signature.s) });
  // Every input is a circuit variable, so the check is the one the request proof makes.
  const inCircuit = async (c: any) => {
    let ok = false;
    await Provable.runAndCheck(() => {
      const m = message(c);
      const vault = Provable.witness(PublicKey, () => m.vault);
      const commitment = Provable.witness(Group, () => m.commitment);
      const anchor = Provable.witness(Field, () => m.anchor);
      const signature = Provable.witness(Signature, () => sig(c));
      const result = verifyState(signature, { vault, commitment, anchor });
      Provable.asProver(() => {
        ok = result.toBoolean();
      });
    });
    return ok;
  };

  it('pin the vault fields of the message', () => {
    for (const c of file.stateSignatures.cases) {
      const m = message(c);
      expect([m.vault.x.toString(), m.vault.isOdd.toField().toString()]).toEqual([c.vault.x, c.vault.isOdd]);
      expect(c.fields).toEqual([c.vault.x, c.vault.isOdd, c.commitment.x, c.commitment.y, c.anchor]);
    }
  });

  it('verify under the devnet ID inside a circuit', async () => {
    expect(file.stateSignatures.cases.length).toBeGreaterThan(0);
    for (const c of file.stateSignatures.cases) expect(await inCircuit(c)).toBe(true);
  });

  it('are refused when any signed field changes', async () => {
    const c = file.stateSignatures.cases[0];
    const other = file.stateSignatures.cases[1];
    for (const changed of [{ anchor: other.anchor }, { commitment: other.commitment }]) {
      expect(await inCircuit({ ...c, ...changed })).toBe(false);
    }
  });

  it('are refused inside a circuit when signed under the mainnet ID', async () => {
    expect(file.stateSignatures.mainnetState.networkId).toBe('mainnet');
    expect(await inCircuit(file.stateSignatures.mainnetState)).toBe(false);
  });
});
