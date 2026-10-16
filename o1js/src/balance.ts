// The balance commitment B·G + r·H over Pallas. Mirrored by zk-note/src/balance.rs, which
// documents the generator derivation; pinned by test-vectors/zk-note.json.
import { Field, Group, Poseidon, Scalar } from 'o1js';
import { tagToBigint } from './primitives.js';

/** Domain tag seeding the generator derivation. Not one of `TAGS`: that would change the
 * domain-separation vectors. */
export const GENERATOR_SEED = 'toon.zk.generator.v1';

/** Try-and-increment over Poseidon, outside any circuit. Returns the point and the counter at which it stopped. */
export function deriveGenerator(index: number): { point: Group; counter: number } {
  for (let counter = 0; ; counter++) {
    const x = Poseidon.hash([Field(tagToBigint(GENERATOR_SEED)), Field(index), Field(counter)]);
    let y: Field;
    try {
      y = x.mul(x).mul(x).add(5).sqrt();
    } catch {
      continue; // x³ + 5 is not a square
    }
    if (y.isOdd().toBoolean()) y = y.neg();
    return { point: Group.from(x, y), counter };
  }
}

/** The generator for balances. */
export const G = deriveGenerator(0).point;
/** The generator for blinding factors. */
export const H = deriveGenerator(1).point;

/** A balance commitment is a Pallas point. */
export type Commitment = Group;

/** `commit(B, r) = B·G + r·H`. */
export const commit = (balance: Scalar, blinding: Scalar): Commitment =>
  G.scale(balance).add(H.scale(blinding));

/** `rerandomise(C, r') = C + r'·H`: the same balance, blinding `r + r'`. */
export const rerandomise = (c: Commitment, blinding: Scalar): Commitment =>
  c.add(H.scale(blinding));

/** `charge(C, Δ) = C − Δ·G`: `commit(B − Δ, r)`, without opening `C`. */
export const charge = (c: Commitment, delta: Scalar): Commitment => c.sub(G.scale(delta));
