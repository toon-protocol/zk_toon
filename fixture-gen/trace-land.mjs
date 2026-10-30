// Dev tool, not part of the fixtures: prove `land` as prove-local.mjs does and log what the
// zk-prover witness mirrors can't read off the o1js sources, to `$SPIKE_DUMP/snarky-log.json`:
//
// - every call into the OCaml side (`Snarky.field`, `gates`, `group`, `poseidon`) while the final
//   proof is made, with its arguments as `FieldVar`s (`full`, for the Poseidon, `scaleFastUnpack`
//   and `truncateToBits16` calls) and the highest variable index in its result;
// - the input of `AccountUpdate.toInput`, which `AccountUpdate.hash` packs and hashes.
//
// The variable indices are those of `w003_cs003.json`. Usage: SPIKE_DUMP=/tmp/d node trace-land.mjs
import fs from 'fs';
import { Snarky, initializeBindings } from './node_modules/o1js/dist/node/bindings.js';
import { Types } from './node_modules/o1js/dist/node/bindings/mina-transaction/v1/types.js';

await initializeBindings();
const log = [];

const maxVar = (x, seen = new Set()) => {
  if (x === null || typeof x !== 'object' || seen.has(x)) return -1;
  seen.add(x);
  if (Array.isArray(x)) {
    if (x[0] === 1 && typeof x[1] === 'number' && x.length === 2) return x[1];
    let m = -1;
    for (const y of x) m = Math.max(m, maxVar(y, seen));
    return m;
  }
  return -1;
};
const short = (x, d = 0) => {
  if (typeof x === 'bigint') return x.toString();
  if (x === null || typeof x !== 'object') return typeof x === 'function' ? 'fn' : String(x);
  if (Array.isArray(x)) {
    return d > 5 ? '[..]' : '[' + x.slice(0, 12).map((y) => short(y, d + 1)).join(',') + (x.length > 12 ? `,..${x.length}` : '') + ']';
  }
  return '{obj}';
};
const json = (x) => JSON.stringify(x, (k, v) => (typeof v === 'bigint' ? v.toString() : v));

for (const ns of ['field', 'gates', 'group', 'poseidon']) {
  for (const k of Object.keys(Snarky[ns])) {
    const f = Snarky[ns][k];
    Snarky[ns][k] = function (...args) {
      const r = f.apply(this, args);
      // `__spikeMark` is set by prove-local.mjs just before the final proof
      if (globalThis.__spikeMark) {
        const full = ns === 'poseidon' || ns === 'group' || k === 'truncateToBits16';
        log.push({ f: `${ns}.${k}`, args: args.map((a) => short(a)), max: maxVar(r), full: full ? json(args) : undefined });
      }
      return r;
    };
  }
}

const toInput = Types.AccountUpdate.toInput;
const fieldVar = (x) => x?.value ?? x;
Types.AccountUpdate.toInput = function (au) {
  const r = toInput.call(this, au);
  if (globalThis.__spikeMark) {
    log.push({
      f: 'AccountUpdate.toInput',
      fields: json(r.fields?.map(fieldVar)),
      packed: json(r.packed?.map(([f, n]) => [fieldVar(f), n])),
    });
  }
  return r;
};

process.on('exit', () => fs.writeFileSync(`${process.env.SPIKE_DUMP}/snarky-log.json`, JSON.stringify(log)));
await import('./prove-local.mjs');
