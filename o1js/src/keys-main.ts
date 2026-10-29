// `npm run keys -- [--no-cache] <out.json>`: compiles the circuits and the vault and writes their
// verification keys, their hashes and the vault's code hash (`Keys` in keys.ts). `--no-cache` compiles
// without o1js's key cache. The gate builds it twice, the second time with `--no-cache`, checks that the
// files are identical, and uploads the first.
import { writeFileSync } from 'node:fs';
import { Cache } from 'o1js';
import { buildKeys } from './keys.js';

const args = process.argv.slice(2);
const noCache = args.includes('--no-cache');
const [out, ...rest] = args.filter((a) => a !== '--no-cache');
if (!out || rest.length > 0) {
  console.error('usage: npm run keys -- [--no-cache] <out.json>');
  process.exit(2);
}
const keys = await buildKeys(noCache ? { cache: Cache.None } : {});
writeFileSync(out, `${JSON.stringify(keys, null, 2)}\n`);
console.log(`vault code hash: ${keys.vault.codeHash}`);
for (const [name, c] of Object.entries(keys.circuits)) console.log(`${name} verification key hash: ${c.verificationKey.hash}`);
console.log(`wrote ${out}`);
// o1js keeps worker threads alive after compiling.
process.exit(0);
