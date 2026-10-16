// Builds test-vectors/zk-note.json, the one file the Rust primitives and the o1js code both reproduce.
import { Bool, Field, Poseidon } from 'o1js';
import * as p from './primitives.js';
import * as policy from './policy.js';

const s = (f: Field) => f.toString();
const F = (n: bigint | number | string) => Field(n);

const SECRET = 123456789012345678901234567890n;
const SECRET_B = 987654321n;
const DAY = policy.MS_PER_DAY;
const WEEK = policy.SUBSIDY_PERIOD_MS;

export function buildVectors() {
  const tags = Object.fromEntries(
    Object.entries(p.TAGS).map(([k, text]) => [k, { text, field: p.tagToBigint(text).toString() }])
  );

  const poseidon = [[], [0], [1], [1, 2], [1, 2, 3], [1, 2, 3, 4]].map((inputs) => ({
    inputs: inputs.map(String),
    output: s(Poseidon.hash(inputs.map(F))),
  }));

  const domainInputs = [F(1), F(2)];
  const domainSeparation = {
    inputs: domainInputs.map(s),
    outputs: Object.fromEntries(
      Object.values(p.TAGS).map((t) => [t, s(p.hashWithTag(t, domainInputs))])
    ),
  };

  const commitment = [SECRET, SECRET_B, 0n].map((secret) => ({
    secret: secret.toString(),
    commitment: s(p.commitSecret(F(secret))),
  }));

  const depositTime = 1_700_000_000_000n;
  const leaves = [
    { index: 0n, secret: SECRET, size: policy.DEPOSIT_SIZES[0], depositTime },
    { index: 7n, secret: SECRET_B, size: policy.DEPOSIT_SIZES[2], depositTime: depositTime + DAY },
  ].map((l) => {
    const expiry = policy.expiryOf(l.depositTime);
    const c = p.commitSecret(F(l.secret));
    return {
      index: l.index.toString(), commitment: s(c), size: l.size.toString(),
      depositTime: l.depositTime.toString(), expiry: expiry.toString(),
      leaf: s(p.leaf(F(l.index), c, F(l.size), F(l.depositTime), F(expiry))),
    };
  });

  // A note's chain of states: each anchor follows from the nullifier spent before it.
  const chainSecret = F(SECRET);
  const chain: { anchor: string; nullifier: string }[] = [];
  const genesis = p.genesisAnchor(p.commitSecret(chainSecret));
  let anchor = genesis;
  for (let i = 0; i < 3; i++) {
    const n = p.nullifier(chainSecret, anchor);
    chain.push({ anchor: s(anchor), nullifier: s(n) });
    anchor = p.nextAnchor(n);
  }
  const nullifiers = {
    secret: SECRET.toString(),
    genesisAnchor: s(genesis),
    chain,
    nextAnchors: chain.map((c) => s(p.nextAnchor(F(c.nullifier)))),
    // Another secret at the same anchor gives another nullifier.
    otherSecretNullifier: s(p.nullifier(F(SECRET_B), F(chain[0].anchor))),
  };

  const ctx = {
    edge: F(424242), sessionKeyX: F(31337), sessionKeyIsOdd: Bool(true), tier: F(policy.TIERS[1]),
    expiry: F(depositTime + 600_000n),
  };
  const ctxJson = (c: p.RequestContext) => ({
    edge: s(c.edge), sessionKeyX: s(c.sessionKeyX), sessionKeyIsOdd: s(c.sessionKeyIsOdd.toField()),
    tier: s(c.tier), expiry: s(c.expiry),
  });
  const n0 = F(chain[0].nullifier);
  const authTags = [
    ctx,
    { ...ctx, edge: F(424243) },
    { ...ctx, sessionKeyIsOdd: Bool(false) },
    { ...ctx, tier: F(policy.TIERS[0]) },
    { ...ctx, expiry: F(depositTime + 600_001n) },
  ].map((c) => ({ nullifier: s(n0), context: ctxJson(c), tag: s(p.authTag(n0, c)) }));

  const periodNullifiers = [
    [SECRET, 7n, 0n], [SECRET, 7n, 1n], [SECRET, 7n, 2n], [SECRET, 8n, 1n], [SECRET_B, 7n, 1n],
  ].map(([secret, index, period]) => ({
    secret: secret.toString(), index: index.toString(), period: period.toString(),
    periodNullifier: s(p.periodNullifier(F(secret), F(index), F(period))),
  }));

  const creation = 1_690_000_000_000n;
  const periodTimes: bigint[] = [
    creation - 1n, creation, creation + 1n,
    creation + WEEK - 1n, creation + WEEK, creation + WEEK + 1n,
    creation + 2n * WEEK - 1n, creation + 2n * WEEK, creation + 2n * WEEK + 1n,
    creation + 52n * WEEK,
  ];
  const periods = periodTimes.map((now) => {
    const period = policy.subsidyPeriod(creation, now);
    return {
      vaultCreation: creation.toString(), now: now.toString(),
      period: period === undefined ? null : period.toString(),
    };
  });

  const ageTimes = [WEEK - 1n, WEEK, WEEK + 1n, 0n, -1n];
  const ages = ageTimes.map((delta) => ({
    depositTime: depositTime.toString(), now: (depositTime + delta).toString(),
    oldEnough: policy.isOldEnoughForSubsidy(depositTime, depositTime + delta),
  }));

  // Which amounts are tiers, deposit sizes and the smallest tier.
  const amounts = [
    0n, ...policy.TIERS, ...policy.DEPOSIT_SIZES, policy.TIERS[0] + 1n, policy.DEPOSIT_SIZES[0] - 1n,
  ];
  const membership = amounts.map((amount) => ({
    amount: amount.toString(),
    isTier: policy.isTier(amount),
    isDepositSize: policy.isDepositSize(amount),
    isSmallestTier: policy.isSmallestTier(amount),
  }));

  const policyJson = {
    msPerDay: DAY.toString(),
    noteLifetimeMs: policy.NOTE_LIFETIME_MS.toString(),
    minSubsidyAgeMs: policy.MIN_SUBSIDY_AGE_MS.toString(),
    subsidyPeriodMs: policy.SUBSIDY_PERIOD_MS.toString(),
    tiers: policy.TIERS.map(String),
    depositSizes: policy.DEPOSIT_SIZES.map(String),
  };

  return {
    description:
      'Shared zk-note test vectors. Field elements are decimal strings; times are milliseconds. ' +
      'Regenerate with `npm run vectors` in o1js/; the Rust crate and the o1js tests both reproduce every entry.',
    tags, policy: policyJson, poseidon, domainSeparation, commitment, leaves, nullifiers,
    authTags, periodNullifiers, periods, ages, membership,
  };
}
