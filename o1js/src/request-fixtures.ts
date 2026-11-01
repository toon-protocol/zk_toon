// The request-proof fixture set the connector's Rust verifier is tested against (#65): a real
// unsubsidised and a real subsidised `RequestProgram` proof over one note tree, the verification key
// they verify under, and a real proof from another program, which that key must refuse. Every proof is
// built through `buildRequest`, so a caller can pass any tree (#67 passes a real vault's); all times
// are in slots (ADR 0007).
import { Cache, PrivateKey, verify, type JsonProof } from 'o1js';
import type { PublishedKey } from './keys.js';
import { NoteTree } from './note-tree.js';
import { TIERS } from './policy.js';
import { RequestProgram, subsidyPeriodHolds } from './request.js';
import { VECTOR_VAULT_CREATION, buildRequest, defaultSample, sampleTreeFor, type SampleOptions } from './request-sample.js';
import { WithdrawalKind, WithdrawalProgram } from './withdrawal.js';
import { buildWithdrawal, defaultWithdrawal } from './withdrawal-sample.js';

export interface RequestFixtureInputs {
  /** The tree the proofs are over, and the index of the note in it. Default: the sample tree. */
  tree?: NoteTree;
  index?: bigint;
  /** The note and request the proofs are for (its tier, subsidy and vault key are set by the fields below). */
  note?: Partial<SampleOptions>;
  /** The vault's secret key: the key that signs state and the proofs' `vault`. */
  vaultSecret?: bigint;
  /** The vault's creation slot, which the subsidised proof's period counts from. */
  vaultCreation?: bigint;
  /** The slot both requests are made at. */
  requestTime?: bigint;
}

export type PublishedKeyProof = { proof: JsonProof; verificationKey: PublishedKey };

export interface RequestFixtures {
  o1js: string;
  /** The vault creation slot the subsidised proof's period was counted from. */
  vaultCreation: string;
  unsubsidised: { proof: JsonProof };
  subsidised: { proof: JsonProof };
  /** The key both request proofs verify under. */
  verificationKey: PublishedKey;
  /** A real proof of `zk-toon-withdrawal`, under its own key: the committed request key must refuse it. */
  otherProgram: PublishedKeyProof & { name: string };
}

const published = (vk: { data: string; hash: { toString(): string } }): PublishedKey =>
  ({ data: vk.data, hash: vk.hash.toString() });

export async function buildRequestFixtures(
  inputs: RequestFixtureInputs,
  o1js: string,
  { cache = Cache.FileSystemDefault }: { cache?: Cache } = {},
): Promise<RequestFixtures> {
  const base = defaultSample();
  const vaultSecret = inputs.vaultSecret ?? base.vaultSecret;
  const vaultCreation = inputs.vaultCreation ?? VECTOR_VAULT_CREATION;
  const requestTime = inputs.requestTime ?? base.requestTime;
  const options: SampleOptions = { ...base, ...inputs.note, vaultSecret, requestTime };
  if ((inputs.tree === undefined) !== (inputs.index === undefined)) {
    throw new Error('give a tree and the note index together, or neither');
  }
  const { tree, index } = inputs.tree !== undefined ? { tree: inputs.tree, index: inputs.index! } : sampleTreeFor(options);

  const plain = buildRequest(tree, index, { ...options, subsidy: undefined });
  const subsidy = buildRequest(tree, index, {
    ...options, tier: TIERS[0], subsidy: { vaultCreation }, ctx: { ...options.ctx, expiry: requestTime + 1n },
  });
  if (!subsidyPeriodHolds(subsidy.pub, vaultCreation)) throw new Error('the subsidised request is not in a period of the vault');

  const request = await RequestProgram.compile({ cache });
  const unsubsidised = (await RequestProgram.unsubsidised(plain.pub, plain.priv)).proof.toJSON();
  const subsidised = (await RequestProgram.subsidised(subsidy.pub, subsidy.priv, subsidy.vaultCreation)).proof.toJSON();
  for (const [proof, label] of [[unsubsidised, 'unsubsidised'], [subsidised, 'subsidised']] as const) {
    if (!(await verify(proof, request.verificationKey))) throw new Error(`the ${label} proof does not verify`);
  }

  const withdrawal = await WithdrawalProgram.compile({ cache });
  const w = buildWithdrawal(tree, {
    ...defaultWithdrawal(WithdrawalKind.ownership), secret: options.secret, index, size: options.size,
    depositTime: options.depositTime, requestTime, stateKey: PrivateKey.fromBigInt(vaultSecret),
  });
  const other = (await WithdrawalProgram.ownership(w.pub, w.priv)).proof.toJSON();
  if (!(await verify(other, withdrawal.verificationKey))) throw new Error('the withdrawal proof does not verify');

  return {
    o1js,
    vaultCreation: vaultCreation.toString(),
    unsubsidised: { proof: unsubsidised },
    subsidised: { proof: subsidised },
    verificationKey: published(request.verificationKey),
    otherProgram: { name: WithdrawalProgram.name, proof: other, verificationKey: published(withdrawal.verificationKey) },
  };
}
