// `npm run request-fixtures -- [out-dir]`, with the lightnet up: runs a real vault (`recorded-vault.ts`),
// proves the request-proof fixture set (`request-fixtures.ts`) over its note tree, and writes
// `recorded-vault.json` and `request-proofs.json` to `test-vectors/request-proofs/`, or to `out-dir`. A rerun
// makes a new vault and new proofs, so both files change; the key does not change unless the circuit does.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Field } from 'o1js';
import { ARCHIVE, MINA, connectLightnet } from './lightnet.js';
import { MIN_SUBSIDY_AGE_SLOTS } from './policy.js';
import { commitSecret, genesisAnchor, nullifier } from './primitives.js';
import { recordVault } from './recorded-vault.js';
import { buildRequestFixtures } from './request-fixtures.js';
import { defaultSample, sampleTreeFor } from './request-sample.js';

const DEFAULT_OUT = new URL('../../test-vectors/request-proofs/', import.meta.url).pathname;
const args = process.argv.slice(2);
if (args.length > 1) {
  console.error('usage: npm run request-fixtures -- [out-dir]');
  process.exit(2);
}
const out = args[0] ?? DEFAULT_OUT;
const o1js = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.o1js;

const { sender, release } = await connectLightnet();
const run = await recordVault({ mina: MINA, archive: ARCHIVE }, sender).finally(release);

const { note, slot } = run;
const fixtures = await buildRequestFixtures({
  tree: run.tree, index: run.index, vaultSecret: run.stateKey.toBigInt(), vaultCreation: run.creationTime,
  requestTime: slot,
  // The chain has not reached this slot: a note's 7 days are 37 hours of a 20-second lightnet, and a deposit
  // can't be named in the past. See docs/verification-keys.md.
  subsidisedRequestTime: note.depositTime + MIN_SUBSIDY_AGE_SLOTS,
  note: { ...note, ctx: { ...defaultSample().ctx, expiry: slot + 1n } },
}, o1js);

// What the recording must not hold: a real root of another tree, and a real nullifier of another note.
const otherSecret = Field(987654321n);
const named = {
  consumedNullifier: run.consumedNullifier.toString(),
  absentRoot: sampleTreeFor(defaultSample()).tree.root.toString(),
  absentNullifier: nullifier(otherSecret, genesisAnchor(commitSecret(otherSecret))).toString(),
};

mkdirSync(out, { recursive: true });
writeFileSync(join(out, 'recorded-vault.json'), `${JSON.stringify({ ...run.recording, named }, null, 2)}\n`);
writeFileSync(join(out, 'request-proofs.json'), `${JSON.stringify(fixtures, null, 2)}\n`);
console.log(`request verification key hash: ${fixtures.verificationKey.hash}`);
console.log(`wrote recorded-vault.json and request-proofs.json to ${out}`);
// o1js keeps worker threads alive after compiling.
process.exit(0);
