// Builds request-proof inputs outside any circuit, for the tests and for the shared vectors.
import { Bool, Field, Group, PrivateKey, Scalar, Signature } from 'o1js';
import { commit, rerandomise } from './balance.js';
import { NoteTree } from './note-tree.js';
import { DEPOSIT_SIZES, TIERS, expiryOf, subsidyPeriod } from './policy.js';
import {
  authTag, commitSecret, genesisAnchor, nextAnchor, nullifier, periodNullifier, type RequestContext,
} from './primitives.js';
import { RequestPrivate, RequestPublic } from './request.js';
import { stateFields } from './state.js';

export interface SampleOptions {
  secret: bigint;
  /** Other deposits already in the tree, so the note is not at index 0. */
  before: number;
  size: bigint;
  depositTime: bigint;
  requestTime: bigint;
  tier: bigint;
  /** A signed state; otherwise the note is at genesis. */
  signed: boolean;
  /** A signed state's place in the note's chain of states: 1 (the default) is genesis's successor. */
  step?: number;
  /** Balance and blinding of a signed state; a genesis state's balance is the deposit size. */
  balance: bigint;
  blinding: bigint;
  rerandom: bigint;
  vaultSecret: bigint;
  /** The edge is the vault key's x-coordinate, the key the zk edge signs state under. */
  ctx: { sessionKeyX: bigint; sessionKeyIsOdd: boolean; expiry: bigint };
  /** A subsidised request, in a vault created at `vaultCreation`; otherwise unsubsidised. */
  subsidy?: { vaultCreation: bigint };
}

export const defaultSample = (): SampleOptions => {
  const depositTime = 1_700_000_000_000n;
  return {
    secret: 123456789012345678901234567890n, before: 3, size: DEPOSIT_SIZES[0], depositTime,
    requestTime: depositTime + 8n * 86_400_000n, tier: TIERS[1], signed: false,
    balance: 4_000_000_000n, blinding: 777_000_111n, rerandom: 424_242n, vaultSecret: 1n,
    ctx: { sessionKeyX: 31337n, sessionKeyIsOdd: true, expiry: depositTime + 9n * 86_400_000n },
  };
};

const sc = (n: bigint) => Scalar.from(n);
const F = (n: bigint) => Field(n);

export interface Sample {
  pub: RequestPublic;
  priv: RequestPrivate;
  tree: NoteTree;
  /** Values a test may rebuild around: the vault key, the state's commitment, and the chain's earlier steps. */
  vaultKey: PrivateKey;
  stateCommitment: Group;
  context: RequestContext;
  /** The vault's creation time, the subsidised method's extra private input; zero when unsubsidised. */
  vaultCreation: Field;
}

/**
 * The anchor of a note's state `step` steps after genesis, and the nullifier and anchor of the state
 * before it (zero at genesis): each state's anchor follows from the nullifier its predecessor spent.
 */
export function stateChain(secret: Field, step: number) {
  let anchor = genesisAnchor(commitSecret(secret));
  let prevNullifier = F(0n);
  let prevAnchor = F(0n);
  for (let i = 0; i < step; i++) {
    prevAnchor = anchor;
    prevNullifier = nullifier(secret, prevAnchor);
    anchor = nextAnchor(prevNullifier);
  }
  return { anchor, prevNullifier, prevAnchor };
}

export function buildSample(o: SampleOptions): Sample {
  const tree = new NoteTree();
  for (let i = 0; i < o.before; i++) {
    tree.append({ commitment: commitSecret(F(BigInt(i + 1))), size: F(DEPOSIT_SIZES[0]), depositTime: F(o.depositTime) });
  }
  const index = tree.append({ commitment: commitSecret(F(o.secret)), size: F(o.size), depositTime: F(o.depositTime) });
  return buildRequest(tree, index, o);
}

/** Inputs for the note at `index` of `tree`, which must hold that note; `o.before` is ignored. */
export function buildRequest(tree: NoteTree, index: bigint, o: SampleOptions): Sample {
  const secret = F(o.secret);
  const vaultKey = PrivateKey.fromBigInt(o.vaultSecret);
  const vault = vaultKey.toPublicKey();
  const balance = o.signed ? o.balance : o.size;
  const stateCommitment = commit(sc(balance), sc(o.blinding));

  const { anchor, prevNullifier, prevAnchor } = stateChain(secret, o.signed ? o.step ?? 1 : 0);
  const signature = o.signed
    ? Signature.create(vaultKey, stateFields({ vault, commitment: stateCommitment, anchor }))
    : Signature.create(vaultKey, [F(0n)]);

  const context: RequestContext = {
    edge: vault.x, sessionKeyX: F(o.ctx.sessionKeyX), sessionKeyIsOdd: Bool(o.ctx.sessionKeyIsOdd),
    tier: F(o.tier), expiry: F(o.ctx.expiry),
  };
  const n = nullifier(secret, anchor);
  // A request before the vault's creation has no period; the sample still builds, and fails to prove.
  const period = o.subsidy ? subsidyPeriod(o.subsidy.vaultCreation, o.requestTime) ?? 0n : 0n;
  const pub = new RequestPublic({
    vault, root: tree.root, requestTime: F(o.requestTime), tier: F(o.tier), nullifier: n,
    tag: authTag(n, context), commitment: rerandomise(stateCommitment, sc(o.rerandom)),
    subsidised: Bool(o.subsidy !== undefined), period: F(period),
    periodNullifier: o.subsidy ? periodNullifier(secret, F(index), F(period)) : F(0n),
  });
  const priv = new RequestPrivate({
    secret, index: F(index), size: F(o.size), depositTime: F(o.depositTime), expiry: F(expiryOf(o.depositTime)),
    path: tree.witness(index), balance: F(balance), blinding: sc(o.blinding), rerandomBlinding: sc(o.rerandom),
    anchor, isGenesis: Bool(!o.signed), signature, prevNullifier, prevAnchor,
    edge: context.edge, sessionKeyX: context.sessionKeyX, sessionKeyIsOdd: context.sessionKeyIsOdd,
    requestExpiry: context.expiry,
  });
  const vaultCreation = F(o.subsidy?.vaultCreation ?? 0n);
  return { pub, priv, tree, vaultKey, stateCommitment, context, vaultCreation };
}

/** The vault creation time of the subsidised vector samples: 10 days before the default deposit. */
const VECTOR_VAULT_CREATION = defaultSample().depositTime - 10n * 86_400_000n;

/**
 * The samples the shared vector file pins: one genesis state and one signed state, unsubsidised; then
 * subsidised, a genesis state in period 2 and a signed state of the same note in period 3.
 */
export const VECTOR_SAMPLES: SampleOptions[] = [
  defaultSample(),
  { ...defaultSample(), signed: true, before: 5 },
  { ...defaultSample(), tier: TIERS[0], subsidy: { vaultCreation: VECTOR_VAULT_CREATION } },
  {
    ...defaultSample(), tier: TIERS[0], signed: true, step: 2, subsidy: { vaultCreation: VECTOR_VAULT_CREATION },
    requestTime: VECTOR_VAULT_CREATION + 3n * 7n * 86_400_000n,
    ctx: { ...defaultSample().ctx, expiry: VECTOR_VAULT_CREATION + 3n * 7n * 86_400_000n + 60_000n },
  },
];

/** A sample's public inputs, and the private values Rust needs to recompute the derived ones. */
export function requestVector(s: Sample, o: SampleOptions) {
  const str = (f: Field) => f.toString();
  const pt = (g: Group) => ({ x: str(g.x), y: str(g.y) });
  return {
    /** The public input as o1js flattens it into a JsonProof's `publicInput`, in `RequestPublic`'s field order. */
    publicInput: RequestPublic.toFields(s.pub).map(str),
    public: {
      vault: { x: str(s.pub.vault.x), isOdd: str(s.pub.vault.isOdd.toField()) },
      root: str(s.pub.root), requestTime: str(s.pub.requestTime), tier: str(s.pub.tier),
      nullifier: str(s.pub.nullifier), tag: str(s.pub.tag), commitment: pt(s.pub.commitment),
      subsidised: s.pub.subsidised.toBoolean(), period: str(s.pub.period), periodNullifier: str(s.pub.periodNullifier),
    },
    private: {
      secret: o.secret.toString(), index: str(s.priv.index), size: str(s.priv.size),
      depositTime: str(s.priv.depositTime), expiry: str(s.priv.expiry),
      balance: str(s.priv.balance), blinding: o.blinding.toString(), rerandomBlinding: o.rerandom.toString(),
      anchor: str(s.priv.anchor), isGenesis: s.priv.isGenesis.toBoolean(),
      signature: { r: str(s.priv.signature.r), s: s.priv.signature.s.toBigInt().toString() },
      prevNullifier: str(s.priv.prevNullifier), prevAnchor: str(s.priv.prevAnchor),
      context: {
        edge: str(s.context.edge), sessionKeyX: str(s.context.sessionKeyX),
        sessionKeyIsOdd: str(s.context.sessionKeyIsOdd.toField()), tier: str(s.context.tier), expiry: str(s.context.expiry),
      },
      stateCommitment: pt(s.stateCommitment),
      // The subsidised method's extra private input; absent for an unsubsidised request.
      ...(o.subsidy ? { vaultCreation: o.subsidy.vaultCreation.toString() } : {}),
    },
  };
}
