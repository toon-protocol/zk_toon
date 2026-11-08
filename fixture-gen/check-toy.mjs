// Check that the numbered dump of `prove-toy.mjs` is laid out as `regenerate.sh` assumes.
// Usage: node check-toy.mjs <dir>
import fs from 'fs';

const dir = process.argv[2];
const witness = (f) => JSON.parse(fs.readFileSync(`${dir}/${f}.json`, 'utf8'));
const expect = (ok, what) => { if (!ok) { console.error(`unexpected toy dump: ${what}`); process.exit(1); } };
// [witness file, circuit it belongs to, public input size]: both outer step circuits and the wrap
// circuit (40 public inputs) that follows each.
for (const [f, size] of [['w003_cs006', 34], ['w004_cs008', 40], ['w005_cs007', 34], ['w006_cs008', 40]]) {
  expect(witness(f).public_input_size === size, `${f} has ${witness(f).public_input_size} public inputs, not ${size}`);
}
// The step proof of `recurse` verifies a proof, so its first unfinalized proof is real: `should_finalize` (field 31) is 1.
expect(witness('w005_cs007').external[31] === '1', 'recurse does not finalize a previous proof');
expect(witness('w003_cs006').external[31] === '0', 'plain finalizes a previous proof');
for (const f of ['stepproof002.b64', 'stepproof003.b64', 'cs006_gates.json', 'cs007_gates.json', 'cs008_gates.json']) {
  expect(fs.existsSync(`${dir}/${f}`), `missing ${f}`);
}
