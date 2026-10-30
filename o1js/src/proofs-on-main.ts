// `npm run proofs-on -- <report.json>`: fails unless every test of the named proofs-on set ran once and
// passed, in a vitest JSON report (`npm test -- --reporter=default --reporter=json --outputFile=<report.json>`).
import { readFileSync } from 'node:fs';
import { PROOFS_ON, proofsOnProblems } from './proofs-on.js';

const path = process.argv[2];
if (!path) {
  console.error('usage: npm run proofs-on -- <vitest JSON report>');
  process.exit(2);
}
const problems = proofsOnProblems(JSON.parse(readFileSync(path, 'utf8')));
if (problems.length > 0) {
  console.error(`proofs-on set incomplete:\n${problems.map((p) => `  ${p}`).join('\n')}`);
  process.exit(1);
}
console.log(`proofs-on tests passed: ${Object.keys(PROOFS_ON).length} (${Object.keys(PROOFS_ON).join(', ')})`);
