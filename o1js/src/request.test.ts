import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Bool, Field, Group, PrivateKey, Provable, Scalar, Signature, verify } from 'o1js';
import { commit, rerandomise } from './balance.js';
import { TIERS, expiryOf } from './policy.js';
import { authTag, commitSecret, genesisAnchor, nextAnchor, nullifier } from './primitives.js';
import { RequestPrivate, RequestProgram, RequestPublic, checkUnsubsidised } from './request.js';
import { VECTOR_SAMPLES, buildSample, defaultSample, requestVector, type SampleOptions } from './request-sample.js';
import { stateFields } from './state.js';

// Proofs off: the constraints are checked, no proof is made.
const holds = async (pub: RequestPublic, priv: RequestPrivate) => {
  try {
    await Provable.runAndCheck(() => {
      const p = Provable.witness(RequestPublic, () => pub);
      const w = Provable.witness(RequestPrivate, () => priv);
      checkUnsubsidised(p, w);
    });
    return true;
  } catch {
    return false;
  }
};
const sample = (o: Partial<SampleOptions> = {}) => buildSample({ ...defaultSample(), ...o });
const signedSample = (o: Partial<SampleOptions> = {}) => sample({ signed: true, ...o });
const withPub = (s: { pub: RequestPublic }, over: Partial<RequestPublic>) => new RequestPublic({ ...s.pub, ...over });
const withPriv = (s: { priv: RequestPrivate }, over: Partial<RequestPrivate>) => new RequestPrivate({ ...s.priv, ...over });

describe('request proof constraints', () => {
  it('hold for a genesis state', async () => {
    const s = sample();
    expect(await holds(s.pub, s.priv)).toBe(true);
  });

  it('hold for a signed state', async () => {
    const s = signedSample();
    expect(await holds(s.pub, s.priv)).toBe(true);
  });

  it('fail when the balance is below b', async () => {
    const s = signedSample({ balance: TIERS[1] - 1n });
    expect(await holds(s.pub, s.priv)).toBe(false);
    // The same state covers a smaller tier.
    const ok = signedSample({ balance: TIERS[1] - 1n, tier: TIERS[0] });
    expect(await holds(ok.pub, ok.priv)).toBe(true);
  });

  it('fail when the balance is below b even by wrapping', async () => {
    const s = signedSample({ balance: 0n });
    expect(await holds(s.pub, s.priv)).toBe(false);
  });

  it('fail for an expired note', async () => {
    const o = defaultSample();
    const expiry = expiryOf(o.depositTime);
    const last = sample({ requestTime: expiry - 1n });
    expect(await holds(last.pub, last.priv)).toBe(true);
    for (const requestTime of [expiry, expiry + 1n]) {
      const s = sample({ requestTime });
      expect(await holds(s.pub, s.priv)).toBe(false);
    }
  });

  it('fail for a wrong anchor', async () => {
    // Genesis flagged, but another anchor.
    const g = sample();
    const bad = Field(5);
    const n = nullifier(g.priv.secret, bad);
    const a = withPriv(g, { anchor: bad });
    const pa = withPub(g, { nullifier: n, tag: authTag(n, g.context) });
    expect(await holds(pa, a)).toBe(false);

    // A signed state whose anchor is not nextAnchor(prevN), correctly signed.
    const s = signedSample();
    const anchor = Field(6);
    const sig = Signature.create(s.vaultKey, stateFields({ vault: s.pub.vault, commitment: s.stateCommitment, anchor }));
    const n2 = nullifier(s.priv.secret, anchor);
    expect(await holds(withPub(s, { nullifier: n2, tag: authTag(n2, s.context) }), withPriv(s, { anchor, signature: sig }))).toBe(false);
  });

  it('fail for a genesis balance other than the deposit size', async () => {
    const g = sample();
    const balance = g.priv.balance.add(1);
    const c = commit(Scalar.from(balance.toBigInt()), Scalar.from(777_000_111n));
    const pub = withPub(g, { commitment: rerandomise(c, Scalar.from(424_242n)) });
    expect(await holds(pub, withPriv(g, { balance }))).toBe(false);
  });

  it('fail for a state signed by another key', async () => {
    const s = signedSample();
    const other = PrivateKey.fromBigInt(2n);
    const sig = Signature.create(other, stateFields({ vault: s.pub.vault, commitment: s.stateCommitment, anchor: s.priv.anchor }));
    expect(await holds(s.pub, withPriv(s, { signature: sig }))).toBe(false);
  });

  it('fail for a signed state flagged as genesis, and for a genesis state flagged as signed', async () => {
    const s = signedSample();
    expect(await holds(s.pub, withPriv(s, { isGenesis: Bool(true) }))).toBe(false);
    const g = sample();
    expect(await holds(g.pub, withPriv(g, { isGenesis: Bool(false) }))).toBe(false);
  });

  it('fail for a tag bound to another context', async () => {
    const s = sample();
    const other = { ...s.context, tier: Field(TIERS[0]) };
    expect(await holds(withPub(s, { tag: authTag(s.pub.nullifier, other) }), s.priv)).toBe(false);
    // A tag over another nullifier.
    expect(await holds(withPub(s, { tag: authTag(Field(99), s.context) }), s.priv)).toBe(false);
    // A tag over a request expiry the prover did not use.
    expect(await holds(withPub(s, { tag: authTag(s.pub.nullifier, { ...s.context, expiry: Field(1) }) }), s.priv)).toBe(false);
  });

  it('fail for a root the note is not in', async () => {
    const s = sample();
    expect(await holds(withPub(s, { root: s.pub.root.add(1) }), s.priv)).toBe(false);
    // A witness for another index.
    expect(await holds(s.pub, withPriv(s, { index: s.priv.index.add(1) }))).toBe(false);
  });

  it('fail for a signed state whose previous nullifier is not from this secret', async () => {
    const s = signedSample();
    const prevAnchor = genesisAnchor(commitSecret(s.priv.secret));
    const prevNullifier = nullifier(Field(31337), prevAnchor); // another note's secret
    const anchor = nextAnchor(prevNullifier);
    const sig = Signature.create(s.vaultKey, stateFields({ vault: s.pub.vault, commitment: s.stateCommitment, anchor }));
    const n = nullifier(s.priv.secret, anchor);
    const pub = withPub(s, { nullifier: n, tag: authTag(n, s.context) });
    expect(await holds(pub, withPriv(s, { anchor, prevNullifier, prevAnchor, signature: sig }))).toBe(false);
  });

  it('fail when the re-randomised commitment is of another balance', async () => {
    const s = sample();
    const other = rerandomise(commit(Scalar.from(1n), Scalar.from(777_000_111n)), Scalar.from(424_242n));
    expect(await holds(withPub(s, { commitment: other }), s.priv)).toBe(false);
  });

  it('fail when the subsidy fields are set', async () => {
    const s = sample();
    expect(await holds(withPub(s, { subsidised: Bool(true) }), s.priv)).toBe(false);
    expect(await holds(withPub(s, { period: Field(1) }), s.priv)).toBe(false);
    expect(await holds(withPub(s, { periodNullifier: Field(1) }), s.priv)).toBe(false);
  });

  it('fail for an expiry that is not expiryOf(depositTime)', async () => {
    const s = sample();
    expect(await holds(s.pub, withPriv(s, { expiry: s.priv.expiry.add(1) }))).toBe(false);
  });
});

describe('request proof', () => {
  it('compiles, then proves and verifies a genesis and a signed request', async () => {
    const { verificationKey } = await RequestProgram.compile();
    for (const s of [sample(), signedSample()]) {
      const { proof } = await RequestProgram.unsubsidised(s.pub, s.priv);
      expect(await verify(proof, verificationKey)).toBe(true);
      expect(proof.publicInput.nullifier.toString()).toBe(s.pub.nullifier.toString());
    }
  }, 900_000);
});

describe('request proof vectors', () => {
  const file = JSON.parse(readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8'));
  it('are reproduced, and satisfy the constraints', async () => {
    expect(file.requestProofs.length).toBe(VECTOR_SAMPLES.length);
    for (const [i, o] of VECTOR_SAMPLES.entries()) {
      const s = buildSample(o);
      expect(requestVector(s, o)).toEqual(file.requestProofs[i]);
      expect(await holds(s.pub, s.priv)).toBe(true);
    }
  });
});
