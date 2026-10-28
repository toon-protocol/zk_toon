// Builds request-proof inputs outside any circuit, for the tests and for the shared vectors.
import { Bool, Field, Group, PrivateKey, Scalar, Signature } from 'o1js';
import { commit, rerandomise } from './balance.js';
import { NoteTree } from './note-tree.js';
import { DEPOSIT_SIZES, TIERS, expiryOf } from './policy.js';
import { authTag, commitSecret, genesisAnchor, nextAnchor, nullifier, type RequestContext } from './primitives.js';
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
  /** Balance and blinding of a signed state; a genesis state's balance is the deposit size. */
  balance: bigint;
  blinding: bigint;
  rerandom: bigint;
  vaultSecret: bigint;
  ctx: { edge: bigint; sessionKeyX: bigint; sessionKeyIsOdd: boolean; expiry: bigint };
}

export const defaultSample = (): SampleOptions => {
  const depositTime = 1_700_000_000_000n;
  return {
    secret: 123456789012345678901234567890n, before: 3, size: DEPOSIT_SIZES[0], depositTime,
    requestTime: depositTime + 8n * 86_400_000n, tier: TIERS[1], signed: false,
    balance: 4_000_000_000n, blinding: 777_000_111n, rerandom: 424_242n, vaultSecret: 1n,
    ctx: { edge: 424242n, sessionKeyX: 31337n, sessionKeyIsOdd: true, expiry: depositTime + 9n * 86_400_000n },
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
}

/**
 * `existing` is a tree that already holds the note, at `index` (a vault's own); otherwise a tree is built
 * with `o.before` other deposits ahead of the note.
 */
export function buildSample(o: SampleOptions, existing?: { tree: NoteTree; index: bigint }): Sample {
  const secret = F(o.secret);
  const commitment = commitSecret(secret);
  const tree = existing?.tree ?? new NoteTree();
  let index = existing?.index ?? 0n;
  if (!existing) {
    for (let i = 0; i < o.before; i++) {
      tree.append({ commitment: commitSecret(F(BigInt(i + 1))), size: F(DEPOSIT_SIZES[0]), depositTime: F(o.depositTime) });
    }
    index = tree.append({ commitment, size: F(o.size), depositTime: F(o.depositTime) });
  }

  const vaultKey = PrivateKey.fromBigInt(o.vaultSecret);
  const vault = vaultKey.toPublicKey();
  const genesis = genesisAnchor(commitment);
  const balance = o.signed ? o.balance : o.size;
  const stateCommitment = commit(sc(balance), sc(o.blinding));

  let anchor = genesis;
  let prevNullifier = F(0n);
  let prevAnchor = F(0n);
  let signature = Signature.create(vaultKey, [F(0n)]);
  if (o.signed) {
    prevAnchor = genesis;
    prevNullifier = nullifier(secret, prevAnchor);
    anchor = nextAnchor(prevNullifier);
    signature = Signature.create(vaultKey, stateFields({ vault, commitment: stateCommitment, anchor }));
  }

  const context: RequestContext = {
    edge: F(o.ctx.edge), sessionKeyX: F(o.ctx.sessionKeyX), sessionKeyIsOdd: Bool(o.ctx.sessionKeyIsOdd),
    tier: F(o.tier), expiry: F(o.ctx.expiry),
  };
  const n = nullifier(secret, anchor);
  const pub = new RequestPublic({
    vault, root: tree.root, requestTime: F(o.requestTime), tier: F(o.tier), nullifier: n,
    tag: authTag(n, context), commitment: rerandomise(stateCommitment, sc(o.rerandom)),
    subsidised: Bool(false), period: F(0n), periodNullifier: F(0n),
  });
  const priv = new RequestPrivate({
    secret, index: F(index), size: F(o.size), depositTime: F(o.depositTime), expiry: F(expiryOf(o.depositTime)),
    path: tree.witness(index), balance: F(balance), blinding: sc(o.blinding), rerandomBlinding: sc(o.rerandom),
    anchor, isGenesis: Bool(!o.signed), signature, prevNullifier, prevAnchor,
    edge: context.edge, sessionKeyX: context.sessionKeyX, sessionKeyIsOdd: context.sessionKeyIsOdd,
    requestExpiry: context.expiry,
  });
  return { pub, priv, tree, vaultKey, stateCommitment, context };
}

/** The samples the shared vector file pins: one genesis state and one signed state. */
export const VECTOR_SAMPLES: SampleOptions[] = [defaultSample(), { ...defaultSample(), signed: true, before: 5 }];

/** A sample's public inputs, and the private values Rust needs to recompute the derived ones. */
export function requestVector(s: Sample, o: SampleOptions) {
  const str = (f: Field) => f.toString();
  const pt = (g: Group) => ({ x: str(g.x), y: str(g.y) });
  return {
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
    },
  };
}
