// The gate's check that the named proofs-on set ran: every named test present once, and passed.
import { describe, expect, it } from 'vitest';
import { PROOFS_ON, proofsOnProblems } from './proofs-on.js';

const NAMES = Object.values(PROOFS_ON);

/** A vitest JSON report holding the given tests, one file each. */
function report(tests: { title: string; status: string }[]) {
  return {
    testResults: tests.map((t, i) => ({
      name: `/repo/o1js/src/file-${i}.test.ts`,
      assertionResults: [{ title: t.title, fullName: `suite ${t.title}`, ancestorTitles: ['suite'], status: t.status }],
    })),
  };
}
const allPassed = () => NAMES.map((title) => ({ title, status: 'passed' }));

describe('the proofs-on set', () => {
  it('names the request proof, close, escape, defeat and subsidised proof, and the vault compile', () => {
    expect(Object.keys(PROOFS_ON).sort()).toEqual(['close', 'defeat', 'escape', 'request', 'subsidised', 'vault']);
    expect(new Set(NAMES).size).toBe(NAMES.length);
  });

  it('passes a run in which every named test passed, among others', () => {
    expect(proofsOnProblems(report([...allPassed(), { title: 'some other test', status: 'skipped' }]))).toEqual([]);
  });

  it('fails a run in which a named test was skipped, todo or failed', () => {
    for (const status of ['skipped', 'pending', 'todo', 'failed']) {
      const tests = allPassed();
      tests[3] = { ...tests[3], status };
      expect(proofsOnProblems(report(tests))).toEqual([`${NAMES[3]}: ${status}, not passed`]);
    }
  });

  it('fails a run missing a named test, or holding one twice', () => {
    expect(proofsOnProblems(report(allPassed().slice(1)))).toEqual([`${NAMES[0]}: missing`]);
    expect(proofsOnProblems(report([...allPassed(), { title: NAMES[2], status: 'passed' }])))
      .toEqual([`${NAMES[2]}: ran 2 times`]);
  });

  it('fails an empty or malformed report', () => {
    expect(proofsOnProblems({ testResults: [] })).toHaveLength(NAMES.length);
    expect(proofsOnProblems({})).toEqual(['not a vitest JSON report']);
  });
});
