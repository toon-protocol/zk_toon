// Every derived value of a zk note. Mirrored byte for byte by zk-note/src/lib.rs and
// pinned by test-vectors/zk-note.json.
import { Bool, Field, Poseidon } from 'o1js';

/** Domain tags: ASCII, at most 31 bytes, read as a little-endian field element. */
export const TAGS = {
  commitment: 'toon.zk.commitment.v1',
  leaf: 'toon.zk.leaf.v1',
  genesisAnchor: 'toon.zk.genesis-anchor.v1',
  nullifier: 'toon.zk.nullifier.v1',
  anchor: 'toon.zk.anchor.v1',
  authTag: 'toon.zk.auth-tag.v1',
  periodNullifier: 'toon.zk.period-nullifier.v1',
  clearance: 'toon.zk.clearance.v1',
} as const;

export function tagToBigint(tag: string): bigint {
  const bytes = new TextEncoder().encode(tag);
  if (bytes.length > 31) throw new Error(`domain tag too long: ${tag}`);
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

/** Poseidon over the Pallas base field with the tag as the first input. */
export function hashWithTag(tag: string, inputs: Field[]): Field {
  return Poseidon.hash([Field(tagToBigint(tag)), ...inputs]);
}

export const commitSecret = (secret: Field) => hashWithTag(TAGS.commitment, [secret]);

/** The leaf commits to index, secret commitment, deposit size, deposit time and expiry. */
export const leaf = (
  index: Field, commitment: Field, size: Field, depositTime: Field, expiry: Field
) => hashWithTag(TAGS.leaf, [index, commitment, size, depositTime, expiry]);

/** The anchor of a note's first state. */
export const genesisAnchor = (commitment: Field) => hashWithTag(TAGS.genesisAnchor, [commitment]);

/** A state is spent once, through its nullifier; only the secret's holder can compute it. */
export const nullifier = (secret: Field, anchor: Field) =>
  hashWithTag(TAGS.nullifier, [secret, anchor]);

/** The next state's anchor follows from the nullifier just spent. */
export const nextAnchor = (nullifierValue: Field) => hashWithTag(TAGS.anchor, [nullifierValue]);

export interface RequestContext {
  /** The zk edge's identity. */
  edge: Field;
  /** The session key's x coordinate and whether y is odd (hashed as 0 or 1). */
  sessionKeyX: Field;
  sessionKeyIsOdd: Bool;
  tier: Field;
  expiry: Field;
}

export const authTag = (nullifierValue: Field, ctx: RequestContext) =>
  hashWithTag(TAGS.authTag, [
    nullifierValue, ctx.edge, ctx.sessionKeyX, ctx.sessionKeyIsOdd.toField(), ctx.tier, ctx.expiry,
  ]);

/** Unlinkable across periods without the secret. */
export const periodNullifier = (secret: Field, index: Field, period: Field) =>
  hashWithTag(TAGS.periodNullifier, [secret, index, period]);
