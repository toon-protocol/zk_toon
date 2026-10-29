// Builds test-vectors/zk-note.json, the one file the Rust primitives and the o1js code both reproduce.
import { Bool, Field, Group, Poseidon, PrivateKey, PublicKey, Scalar, Signature, UInt64 } from 'o1js';
import * as p from './primitives.js';
import * as policy from './policy.js';
import * as bal from './balance.js';
import {
  SUBSIDY_PERIOD_SAMPLES, VECTOR_SAMPLES, buildSample, requestVector, subsidyPeriodVector,
} from './request-sample.js';
import { stateFields, type StateMessage } from './state.js';
import { clearanceFields, signClearance } from './clearance.js';
import { WITHDRAWAL_VECTOR_SAMPLES, withdrawalVector } from './withdrawal-sample.js';
import { NULLIFIER_SET_HEIGHT, PendingEscape, PendingEscapes } from './vault.js';

const s = (f: Field) => f.toString();
const F = (n: bigint | number | string) => Field(n);

const SECRET = 123456789012345678901234567890n;
const SECRET_B = 987654321n;
/** Secrets of the vault keys the zk edge signs state under. */
const VAULT_SECRETS = [1n, 987654321098765432109876543210n];
const DAY = policy.MS_PER_DAY;
const WEEK = policy.SUBSIDY_PERIOD_MS;
const Q = Scalar.ORDER;

const pointJson = (g: Group) => ({ x: s(g.x), y: s(g.y) });
const sc = (n: bigint) => Scalar.from(((n % Q) + Q) % Q);

/** Mina Schnorr under the mainnet network ID, which o1js 3.1.0 cannot produce itself. The nonce is
 * a fixed scalar: any nonce gives a valid signature, only the devnet ID decides acceptance. */
function signMainnet(secret: bigint, fields: Field[]): { r: Field; s: bigint } {
  const pub = Group.generator.scale(sc(secret));
  let k = 1234567890123456789n;
  const R = Group.generator.scale(sc(k));
  if (R.y.isOdd().toBoolean()) k = Q - k;
  const e = Poseidon.hashWithPrefix('MinaSignatureMainnet', [...fields, pub.x, pub.y, R.x]).toBigInt() % Q;
  return { r: R.x, s: (k + e * secret) % Q };
}

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

  // The edge in an auth tag is the x-coordinate of the vault key the zk edge signs state under.
  const [edge, otherEdge] = VAULT_SECRETS.map((secret) => PrivateKey.fromBigInt(secret).toPublicKey().x);
  const ctx = {
    edge, sessionKeyX: F(31337), sessionKeyIsOdd: Bool(true), tier: F(policy.TIERS[1]),
    expiry: F(depositTime + 600_000n),
  };
  const ctxJson = (c: p.RequestContext) => ({
    edge: s(c.edge), sessionKeyX: s(c.sessionKeyX), sessionKeyIsOdd: s(c.sessionKeyIsOdd.toField()),
    tier: s(c.tier), expiry: s(c.expiry),
  });
  const n0 = F(chain[0].nullifier);
  const authTags = [
    ctx,
    { ...ctx, edge: otherEdge },
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

  // A requestTime at and either side of each edge of the window around now.
  const now = depositTime;
  const requestDeltas = [
    0n, -policy.REQUEST_MAX_AGE_MS, -policy.REQUEST_MAX_AGE_MS - 1n,
    policy.REQUEST_MAX_LEAD_MS, policy.REQUEST_MAX_LEAD_MS + 1n,
  ];
  const requestTimes = requestDeltas.map((delta) => ({
    now: now.toString(), requestTime: (now + delta).toString(),
    fresh: policy.isRequestTimeFresh(now + delta, now),
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
    challengeWindowMs: policy.CHALLENGE_WINDOW_MS.toString(),
    requestMaxAgeMs: policy.REQUEST_MAX_AGE_MS.toString(),
    requestMaxLeadMs: policy.REQUEST_MAX_LEAD_MS.toString(),
    tiers: policy.TIERS.map(String),
    depositSizes: policy.DEPOSIT_SIZES.map(String),
  };

  const generators = {
    seed: { text: bal.GENERATOR_SEED, field: p.tagToBigint(bal.GENERATOR_SEED).toString() },
    curveGenerator: pointJson(Group.generator),
    g: { index: '0', counter: bal.deriveGenerator(0).counter.toString(), ...pointJson(bal.G) },
    h: { index: '1', counter: bal.deriveGenerator(1).counter.toString(), ...pointJson(bal.H) },
  };

  const BALANCES: [bigint, bigint][] = [
    [0n, 5n], [10_000_000n, 123456789n], [1_000_000_000n, 987654321987654321n], [7n, Q - 1n],
  ];
  const commitments = BALANCES.map(([balance, blinding]) => ({
    balance: balance.toString(), blinding: blinding.toString(),
    commitment: pointJson(bal.commit(sc(balance), sc(blinding))),
  }));
  const rerandomised = [
    [10_000_000n, 123456789n, 42n], [10_000_000n, 123456789n, Q - 123456789n], [0n, 5n, 1n],
  ].map(([balance, blinding, extra]) => ({
    balance: balance.toString(), blinding: blinding.toString(), extra: extra.toString(),
    rerandomised: pointJson(bal.rerandomise(bal.commit(sc(balance), sc(blinding)), sc(extra))),
    // The same balance committed with blinding r + r'.
    recommitted: pointJson(bal.commit(sc(balance), sc(blinding + extra))),
  }));
  const charged = [
    [10_000_000n, 123456789n, 1n], [10_000_000n, 123456789n, 10_000_000n], [1_000_000_000n, 5n, 250_000_000n],
  ].map(([balance, blinding, delta]) => ({
    balance: balance.toString(), blinding: blinding.toString(), delta: delta.toString(),
    charged: pointJson(bal.charge(bal.commit(sc(balance), sc(blinding)), sc(delta))),
    // The charged balance committed afresh with the same blinding.
    recommitted: pointJson(bal.commit(sc(balance - delta), sc(blinding))),
  }));

  const stateCases = [
    { secret: VAULT_SECRETS[0], balance: 10_000_000n, blinding: 123456789n, anchor: genesis },
    { secret: VAULT_SECRETS[1], balance: 1_000_000_000n, blinding: 5n, anchor: F(chain[1].anchor) },
    { secret: VAULT_SECRETS[1], balance: 0n, blinding: 7n, anchor: F(0) },
  ].map((c) => {
    const key = PrivateKey.fromBigInt(c.secret);
    const vault = key.toPublicKey();
    const commitment = bal.commit(sc(c.balance), sc(c.blinding));
    const msg: StateMessage = { vault, commitment, anchor: c.anchor };
    const fields = stateFields(msg);
    const sig = Signature.create(key, fields);
    return {
      secret: c.secret.toString(), vault: { x: s(vault.x), isOdd: s(vault.isOdd.toField()) },
      balance: c.balance.toString(), blinding: c.blinding.toString(),
      commitment: pointJson(commitment), anchor: s(c.anchor),
      fields: fields.map(s), signature: { r: s(sig.r), s: sig.s.toBigInt().toString() },
    };
  });
  const mainnetState = (() => {
    const base = stateCases[0];
    const sig = signMainnet(BigInt(base.secret), base.fields.map(F));
    return { ...base, signature: { r: s(sig.r), s: sig.s.toString() }, networkId: 'mainnet' };
  })();
  const stateSignatures = { networkId: 'devnet', cases: stateCases, mainnetState };

  // Clearances: the state key signs one nullifier and one destination, under the devnet ID.
  const CLEARANCE_CASES = [
    { stateSecret: 1n, nullifier: F(chain[0].nullifier), destinationSecret: 77n },
    { stateSecret: 1n, nullifier: F(chain[1].nullifier), destinationSecret: 77n },
    { stateSecret: 1n, nullifier: F(chain[0].nullifier), destinationSecret: 78n },
    { stateSecret: VAULT_SECRETS[1], nullifier: F(chain[2].nullifier), destinationSecret: 78n },
  ];
  const key = (k: PublicKey) => ({ x: s(k.x), isOdd: s(k.isOdd.toField()) });
  const clearanceCases = CLEARANCE_CASES.map((c) => {
    const stateKey = PrivateKey.fromBigInt(c.stateSecret);
    const msg = {
      stateKey: stateKey.toPublicKey(), nullifier: c.nullifier,
      destination: PrivateKey.fromBigInt(c.destinationSecret).toPublicKey(),
    };
    const sig = signClearance(stateKey, msg);
    return {
      stateSecret: c.stateSecret.toString(), stateKey: key(msg.stateKey), nullifier: s(c.nullifier),
      destination: key(msg.destination), fields: clearanceFields(msg).map(s),
      signature: { r: s(sig.r), s: sig.s.toBigInt().toString() },
    };
  });
  // The first case signed under the mainnet ID, which a clearance never is: both sides refuse it.
  const mainnetClearance = (() => {
    const base = clearanceCases[0];
    const sig = signMainnet(BigInt(base.stateSecret), base.fields.map(F));
    return { ...base, signature: { r: s(sig.r), s: sig.s.toString() }, networkId: 'mainnet' };
  })();
  const clearances = { networkId: 'devnet', cases: clearanceCases, mainnetClearance };

  const withdrawalProofs = WITHDRAWAL_VECTOR_SAMPLES.map(withdrawalVector);

  const requestProofs = VECTOR_SAMPLES.map((o) => requestVector(buildSample(o), o));
  const subsidyPeriods = SUBSIDY_PERIOD_SAMPLES.map(subsidyPeriodVector);

  // The vault's pending escapes: record hashes, and the map's root after each insert or update, as a
  // challenger replaying the vault's escape events rebuilds it.
  const escapeRecords = [
    { nullifier: F(chain[0].nullifier), nextNullifier: F(chain[1].nullifier), amount: 3_000_000_000n,
      conceded: 10_000_000n, size: 10_000_000_000n, destinationSecret: 77n, deadline: 1_700_172_800_000n },
    { nullifier: F(chain[2].nullifier), nextNullifier: F(12345), amount: 10_000_000_000n,
      conceded: 0n, size: 10_000_000_000n, destinationSecret: 78n, deadline: 1_700_259_200_000n },
  ].map((r) => new PendingEscape({
    nullifier: r.nullifier, nextNullifier: r.nextNullifier, amount: UInt64.from(r.amount),
    conceded: UInt64.from(r.conceded), size: UInt64.from(r.size),
    destination: PrivateKey.fromBigInt(r.destinationSecret).toPublicKey(), deadline: UInt64.from(r.deadline),
  }));
  // The second record raised to 0.5 MINA.
  const raised = new PendingEscape({ ...escapeRecords[1], conceded: UInt64.from(500_000_000n) });
  const records = [...escapeRecords, raised];
  const map = new PendingEscapes();
  const emptyRoot = map.root;
  // Small keys first (an insert, an insert below it, an update), then the records as a reduce writes
  // them: two recorded, the first finished, the second raised.
  const mapOps: [Field, Field][] = [
    [F(5), F(7)], [F(3), F(9)], [F(5), F(0)],
    [records[0].nullifier, records[0].hash()], [records[1].nullifier, records[1].hash()],
    [records[0].nullifier, F(0)], [raised.nullifier, raised.hash()],
  ];
  const updates = mapOps.map(([k, v]) => {
    map.set(k, v);
    return { key: s(k), value: s(v), root: s(map.root) };
  });
  const pendingEscapes = {
    height: NULLIFIER_SET_HEIGHT,
    emptyRoot: s(emptyRoot),
    records: records.map((r) => ({ fields: PendingEscape.toFields(r).map(s), hash: s(r.hash()) })),
    updates,
  };

  return {
    description:
      'Shared zk-note test vectors. Field elements are decimal strings; times are milliseconds. ' +
      'Regenerate with `npm run vectors` in o1js/; the Rust crate and the o1js tests both reproduce every entry.',
    tags, policy: policyJson, poseidon, domainSeparation, commitment, leaves, nullifiers,
    authTags, periodNullifiers, periods, ages, requestTimes, membership,
    generators, balanceCommitments: commitments, rerandomised, charged, stateSignatures,
    requestProofs, clearances, withdrawalProofs, subsidyPeriods, pendingEscapes,
  };
}
