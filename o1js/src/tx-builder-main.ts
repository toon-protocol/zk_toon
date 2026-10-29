// The transaction builder as a process: one JSON request per stdin line, one JSON answer per stdout
// line, in order. See `docs/tx-builder.md`.
//
//   node --import tsx src/tx-builder-main.ts --local [--proofs=off]
//   node --import tsx src/tx-builder-main.ts --mina <graphql url> --archive <archive url> [--proofs=off]
//
// stdout carries only answers: anything o1js prints goes to stderr. Nothing a request carries is printed.
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';

const write = process.stdout.write.bind(process.stdout);
console.log = console.info = console.debug = console.warn = (...args: unknown[]) => console.error(...args);

const { values } = parseArgs({
  options: {
    local: { type: 'boolean', default: false },
    proofs: { type: 'string', default: 'on' },
    mina: { type: 'string' },
    archive: { type: 'string' },
  },
});
if (values.proofs !== 'on' && values.proofs !== 'off') throw Error('--proofs is on or off');
if (!values.local && !values.mina) throw Error('give --local, or --mina <graphql url> and --archive <url>');

// Imported after the console is redirected, so nothing o1js prints while loading reaches stdout.
const { createBuilder } = await import('./tx-builder.js');
const builder = await createBuilder({
  local: values.local, proofs: values.proofs === 'on', mina: values.mina, archive: values.archive,
});

// One request at a time: proving is not reentrant.
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  if (line.trim() === '') continue;
  write((await builder.handle(line)) + '\n');
}
process.exit(0);
