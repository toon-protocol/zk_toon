// The registry's deployment records: one per network, checked in. A registry's address isn't a build output, so it is
// not in the published keys (`keys.ts`). A record says where the registry is and what it looked like when it was seen
// empty and locked: anyone can reproduce that from an archive (ADR 0011). There is no real record yet.
import { readFileSync } from 'node:fs';
import { Experimental, PublicKey } from 'o1js';

export type RegistryDeployment = {
  network: string;
  /** The registry's address, in base58. */
  registry: string;
  /** The slot at which the registry was seen empty and locked. */
  slot: string;
  /** Its action state then: the empty one, as a decimal field. */
  actionState: string;
  /** The hash of the command that deployed it, which is published beside the devnet write-up (`registry-sighting.ts`). */
  transaction: string;
};

export const REGISTRY_DEPLOYMENTS_PATH = new URL('../registry-deployments.json', import.meta.url);

/** What is wrong with a deployment file's contents; empty when each network has one well-formed record. */
export function deploymentProblems(file: unknown): string[] {
  const list = (file as { deployments?: unknown })?.deployments;
  if (!Array.isArray(list)) return ['no "deployments" list'];
  const seen = new Set<string>();
  return list.flatMap((d: Partial<RegistryDeployment>, i) => {
    const at = `deployment ${i}`;
    const problems: string[] = [];
    if (typeof d?.network !== 'string' || d.network === '') problems.push(`${at}: no network`);
    else if (seen.has(d.network)) problems.push(`${at}: a second record for ${d.network}`);
    else seen.add(d.network);
    try {
      PublicKey.fromBase58(d?.registry ?? '');
    } catch {
      problems.push(`${at}: the registry is not an address`);
    }
    if (!/^[0-9]+$/.test(d?.slot ?? '')) problems.push(`${at}: the slot is not a number`);
    if (typeof d?.transaction !== 'string' || d.transaction === '') problems.push(`${at}: no deploy transaction`);
    if (d?.actionState !== Experimental.BatchReducer.initialActionState.toString()) {
      problems.push(`${at}: the action state is not the empty one, so the registry was not seen empty`);
    }
    return problems;
  });
}

/** The checked-in records. Throws if they are malformed. */
export function readDeployments(file: unknown = JSON.parse(readFileSync(REGISTRY_DEPLOYMENTS_PATH, 'utf8'))): RegistryDeployment[] {
  const problems = deploymentProblems(file);
  if (problems.length > 0) throw Error(`registry-deployments.json: ${problems.join('; ')}`);
  return (file as { deployments: RegistryDeployment[] }).deployments;
}
