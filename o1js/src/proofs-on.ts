// The named proofs-on set: the tests that compile the circuits and prove for real, to show that the
// circuits and the vault agree, and that o1js still compiles what zk-prover mirrors. Each is declared by its title here, and the gate fails unless every
// one ran exactly once and passed (`npm run proofs-on -- <vitest JSON report>`). Every other o1js
// test runs with proofs off.
export const PROOFS_ON = {
  request: 'proofs on: a genesis and a signed request proof verify',
  subsidised: 'proofs on: a subsidised request proof verifies',
  close: 'proofs on: a mutual close with a real withdrawal proof pays at the reduce',
  escape: 'proofs on: an escape with a real withdrawal proof is bound to its destination, and pays it after the window',
  defeat: 'proofs on: a real request proof at the next nullifier defeats an escape',
  reduceLimit: 'proofs on: a keeper reduces a vault with more action lists pending than a reduce takes',
  vault: 'proofs on: the vault compiles, and a deployed vault carries the published code hash',
  constants: 'proofs on: the vault and the circuits compile to the same keys under other network constants',
  registry: 'proofs on: a vault registers in one transaction, with the published key, the state init writes and a listing',
  registryExisting: 'proofs on: the registry refuses an address that already has an account',
  registryEarlier: 'proofs on: the registry refuses a vault written to earlier in the same transaction',
  registryLater: 'proofs on: the registry leaves a vault no later write in the same transaction the permissions forbid',
  registryTampered: 'proofs on: the registry refuses a vault changed after its transaction is proved',
  registryOtherKey: 'proofs on: the registry refuses any verification key but the published vault',
  registryNoProof: 'proofs on: nobody adds a registry entry without the registry proof',
  registryRogueKey: 'proofs on: a rogue key under the published hash leaves the vault account stuck',
  registryUris: 'proofs on: two URIs register under one compiled key, and a URI changed after proving is refused',
  landVk: "proofs on: this o1js compiles zk-prover's land program to the pinned verification key",
} as const;

type Assertion = { title?: unknown; status?: unknown };

/** What is wrong with the named set in a vitest JSON report; empty when every named test passed once. */
export function proofsOnProblems(report: unknown): string[] {
  const files = (report as { testResults?: unknown })?.testResults;
  if (!Array.isArray(files)) return ['not a vitest JSON report'];
  const runs = new Map<string, string[]>();
  for (const file of files) {
    for (const a of ((file as { assertionResults?: Assertion[] }).assertionResults ?? [])) {
      if (typeof a.title !== 'string') continue;
      runs.set(a.title, [...(runs.get(a.title) ?? []), String(a.status)]);
    }
  }
  return Object.values(PROOFS_ON).flatMap((title) => {
    const statuses = runs.get(title) ?? [];
    if (statuses.length === 0) return [`${title}: missing`];
    if (statuses.length > 1) return [`${title}: ran ${statuses.length} times`];
    return statuses[0] === 'passed' ? [] : [`${title}: ${statuses[0]}, not passed`];
  });
}
