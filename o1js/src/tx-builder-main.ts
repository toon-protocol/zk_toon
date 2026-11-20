// The transaction builder as a process: one JSON request per stdin line, one JSON answer per stdout
// line, in order. See `docs/tx-builder.md`.
//
//   node --import tsx src/tx-builder-main.ts --local [--proofs=off]
//   node --import tsx src/tx-builder-main.ts --mina <graphql url> --archive <archive url> [--proofs=off] [--keys <verification-keys.json>]
//
// With `--keys` (the file `npm run keys` writes), a vault's generation is found by its code hash among the file's generations
// (ADR 0015), and a vault whose code hash is in none is refused.
//
// stdout carries only answers: anything o1js prints goes to stderr. Nothing a request carries is printed.
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { Keys } from './keys.js';

const write = process.stdout.write.bind(process.stdout);
console.log = console.info = console.debug = console.warn = (...args: unknown[]) => console.error(...args);

const { values } = parseArgs({
  options: {
    local: { type: 'boolean', default: false },
    proofs: { type: 'string', default: 'on' },
    mina: { type: 'string' },
    archive: { type: 'string' },
    keys: { type: 'string' },
  },
});
if (values.proofs !== 'on' && values.proofs !== 'off') throw Error('--proofs is on or off');
if (!values.local && !values.mina) throw Error('give --local, or --mina <graphql url> and --archive <url>');

// Imported after the console is redirected, so nothing o1js prints while loading reaches stdout.
const { createBuilder } = await import('./tx-builder.js');
const builder = await createBuilder({
  local: values.local, proofs: values.proofs === 'on', mina: values.mina, archive: values.archive,
  generations: values.keys ? (JSON.parse(readFileSync(values.keys, 'utf8')) as Keys).generations : undefined,
});

// One request at a time: proving is not reentrant.
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  if (line.trim() === '') continue;
  write((await builder.handle(line)) + '\n');
}
process.exit(0);
