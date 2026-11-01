// `npm run request-fixtures -- [out.json]`: proves the request-proof fixture set (`request-fixtures.ts`) with
// the sample tree and sample vault key, and writes it to `test-vectors/request-proofs/request-proofs.json`, or
// to `out.json`. Proofs are randomised, so a rerun changes the file; the key does not change unless the circuit does.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { buildRequestFixtures } from './request-fixtures.js';

const DEFAULT_OUT = new URL('../../test-vectors/request-proofs/request-proofs.json', import.meta.url).pathname;
const args = process.argv.slice(2);
if (args.length > 1) {
  console.error('usage: npm run request-fixtures -- [out.json]');
  process.exit(2);
}
const out = args[0] ?? DEFAULT_OUT;
const o1js = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.o1js;
const fixtures = await buildRequestFixtures({}, o1js);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(fixtures, null, 2)}\n`);
console.log(`request verification key hash: ${fixtures.verificationKey.hash}`);
console.log(`wrote ${out}`);
// o1js keeps worker threads alive after compiling.
process.exit(0);
