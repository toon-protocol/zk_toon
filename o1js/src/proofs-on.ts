// The named proofs-on set: the tests that compile the circuits and prove for real, to show that the
// circuits and the vault agree. Each is declared by its title here, and the gate fails unless every
// one ran exactly once and passed (`npm run proofs-on -- <vitest JSON report>`). Every other o1js
// test runs with proofs off.
export const PROOFS_ON = {
  request: 'proofs on: a genesis and a signed request proof verify',
  subsidised: 'proofs on: a subsidised request proof verifies',
  close: 'proofs on: a mutual close with a real withdrawal proof pays at the reduce',
  escape: 'proofs on: an escape with a real withdrawal proof is bound to its destination, and pays it after the window',
  defeat: 'proofs on: a real request proof at the next nullifier defeats an escape',
  vault: 'proofs on: the vault compiles, and a deployed vault carries the published code hash',
  constants: 'proofs on: the vault and the circuits compile to the same keys under other network constants',
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
