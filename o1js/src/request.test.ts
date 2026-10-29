import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { Bool, Field, Group, PrivateKey, Provable, Scalar, Signature, VerificationKey, verify } from 'o1js';
import { commit, rerandomise } from './balance.js';
import { TIERS, expiryOf } from './policy.js';
import { authTag, commitSecret, genesisAnchor, nextAnchor, nullifier, periodNullifier } from './primitives.js';
import { RequestPrivate, RequestProgram, RequestPublic, checkSubsidised, checkUnsubsidised } from './request.js';
import { VECTOR_SAMPLES, buildSample, defaultSample, requestVector, type SampleOptions } from './request-sample.js';
import { PROOFS_ON } from './proofs-on.js';
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
const holdsSubsidised = async (pub: RequestPublic, priv: RequestPrivate, vaultCreation: Field) => {
  try {
    await Provable.runAndCheck(() => {
      const p = Provable.witness(RequestPublic, () => pub);
      const w = Provable.witness(RequestPrivate, () => priv);
      const c = Provable.witness(Field, () => vaultCreation);
      checkSubsidised(p, w, c);
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
    const { blinding, rerandom } = defaultSample();
    const c = commit(Scalar.from(balance.toBigInt()), Scalar.from(blinding));
    const pub = withPub(g, { commitment: rerandomise(c, Scalar.from(rerandom)) });
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
    const { blinding, rerandom } = defaultSample();
    const other = rerandomise(commit(Scalar.from(1n), Scalar.from(blinding)), Scalar.from(rerandom));
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

describe('subsidised request proof constraints', () => {
  const DAY = 86_400_000n;
  const { depositTime } = defaultSample();
  // The vault was created 10 days before the deposit; the default request is 8 days after it.
  const vaultCreation = depositTime - 10n * DAY;
  const subsidisedSample = (o: Partial<SampleOptions> = {}) =>
    sample({ tier: TIERS[0], subsidy: { vaultCreation }, ...o });
  const ok = (s: ReturnType<typeof sample>) => holdsSubsidised(s.pub, s.priv, Field(vaultCreation));

  it('hold for a note 7 or more days old, at the smallest tier, in the period of its request time', async () => {
    const s = subsidisedSample();
    expect(s.pub.subsidised.toBoolean()).toBe(true);
    // 18 days after creation is the third week: period 2.
    expect(s.pub.period.toBigInt()).toBe(2n);
    expect(s.pub.periodNullifier.toBigInt()).toBe(periodNullifier(s.priv.secret, s.priv.index, Field(2)).toBigInt());
    expect(await ok(s)).toBe(true);
    expect(await ok(subsidisedSample({ signed: true }))).toBe(true);
    // Exactly 7 days old is old enough.
    expect(await ok(subsidisedSample({ requestTime: depositTime + 7n * DAY }))).toBe(true);
  });

  it('fail for a note younger than 7 days', async () => {
    for (const requestTime of [depositTime + 7n * DAY - 1n, depositTime + DAY, depositTime]) {
      expect(await ok(subsidisedSample({ requestTime }))).toBe(false);
    }
  });

  it('fail for a tier above the smallest', async () => {
    for (const tier of TIERS.slice(1)) expect(await ok(subsidisedSample({ tier }))).toBe(false);
  });

  it('fail for a wrong period number', async () => {
    const s = subsidisedSample();
    for (const period of [1n, 3n, 0n]) {
      const pub = withPub(s, { period: Field(period), periodNullifier: periodNullifier(s.priv.secret, s.priv.index, Field(period)) });
      expect(await holdsSubsidised(pub, s.priv, Field(vaultCreation))).toBe(false);
    }
    // The last instant of a week is still that week, and its first instant is the next.
    const week = 7n * DAY;
    const end = vaultCreation + 3n * week - 1n;
    expect(subsidisedSample({ requestTime: end }).pub.period.toBigInt()).toBe(2n);
    expect(await ok(subsidisedSample({ requestTime: end }))).toBe(true);
    expect(subsidisedSample({ requestTime: end + 1n }).pub.period.toBigInt()).toBe(3n);
    expect(await ok(subsidisedSample({ requestTime: end + 1n }))).toBe(true);
    const late = subsidisedSample({ requestTime: end + 1n });
    const stale = withPub(late, { period: Field(2), periodNullifier: periodNullifier(late.priv.secret, late.priv.index, Field(2)) });
    expect(await holdsSubsidised(stale, late.priv, Field(vaultCreation))).toBe(false);
    // A request time before the vault's creation has no period.
    expect(await holdsSubsidised(s.pub, s.priv, Field(s.pub.requestTime.toBigInt() + 1n))).toBe(false);
  });

  it('fail for a per-period nullifier of another period, index or secret', async () => {
    const s = subsidisedSample();
    for (const pn of [
      periodNullifier(s.priv.secret, s.priv.index, Field(1)),
      periodNullifier(s.priv.secret, s.priv.index.add(1), Field(2)),
      periodNullifier(Field(31337), s.priv.index, Field(2)),
    ]) {
      expect(await holdsSubsidised(withPub(s, { periodNullifier: pn }), s.priv, Field(vaultCreation))).toBe(false);
    }
  });

  it('fail when not flagged subsidised', async () => {
    const s = subsidisedSample();
    expect(await holdsSubsidised(withPub(s, { subsidised: Bool(false) }), s.priv, Field(vaultCreation))).toBe(false);
  });

  it('carry one per-period nullifier for two proofs from one note in one period, and another in the next', async () => {
    const week = 7n * DAY;
    const first = subsidisedSample({ requestTime: depositTime + 7n * DAY, signed: false });
    const second = subsidisedSample({ requestTime: vaultCreation + 3n * week - 1n, signed: true, step: 3 });
    const next = subsidisedSample({ requestTime: vaultCreation + 3n * week, signed: true, step: 3 });
    for (const s of [first, second, next]) expect(await ok(s)).toBe(true);
    // Different states, so different nullifiers: only the per-period nullifier links the two claims.
    expect(first.pub.nullifier.toBigInt()).not.toBe(second.pub.nullifier.toBigInt());
    expect(first.pub.periodNullifier.toBigInt()).toBe(second.pub.periodNullifier.toBigInt());
    expect(next.pub.periodNullifier.toBigInt()).not.toBe(second.pub.periodNullifier.toBigInt());
  });
});

describe('request proof', () => {
  let verificationKey: VerificationKey;
  beforeAll(async () => {
    ({ verificationKey } = await RequestProgram.compile());
  }, 900_000);

  it(PROOFS_ON.request, async () => {
    for (const s of [sample(), signedSample()]) {
      const { proof } = await RequestProgram.unsubsidised(s.pub, s.priv);
      expect(await verify(proof, verificationKey)).toBe(true);
      expect(proof.publicInput.nullifier.toString()).toBe(s.pub.nullifier.toString());
    }
  }, 900_000);

  it(PROOFS_ON.subsidised, async () => {
    const sub = signedSample({ tier: TIERS[0], subsidy: { vaultCreation: defaultSample().depositTime - 10n * 86_400_000n } });
    const { proof } = await RequestProgram.subsidised(sub.pub, sub.priv, sub.vaultCreation);
    expect(await verify(proof, verificationKey)).toBe(true);
    expect(proof.publicInput.subsidised.toBoolean()).toBe(true);
    expect(proof.publicInput.periodNullifier.toString()).toBe(sub.pub.periodNullifier.toString());
  }, 900_000);
});

describe('request proof vectors', () => {
  const file = JSON.parse(readFileSync(new URL('../../test-vectors/zk-note.json', import.meta.url), 'utf8'));
  it('are reproduced, and satisfy the constraints', async () => {
    expect(file.requestProofs.length).toBe(VECTOR_SAMPLES.length);
    for (const [i, o] of VECTOR_SAMPLES.entries()) {
      const s = buildSample(o);
      expect(requestVector(s, o)).toEqual(file.requestProofs[i]);
      if (o.subsidy) expect(await holdsSubsidised(s.pub, s.priv, s.vaultCreation)).toBe(true);
      else expect(await holds(s.pub, s.priv)).toBe(true);
    }
    // Both kinds are pinned, subsidised in two periods.
    const periods = file.requestProofs.filter((e: any) => e.public.subsidised).map((e: any) => e.public.period);
    expect(file.requestProofs.some((e: any) => !e.public.subsidised)).toBe(true);
    expect(new Set(periods).size).toBeGreaterThanOrEqual(2);
  });
});
