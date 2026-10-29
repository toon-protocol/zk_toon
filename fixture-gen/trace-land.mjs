// Dev tool: log every Snarky call made while proving land, with the highest variable index in its result.
import { Snarky, initializeBindings } from './node_modules/o1js/dist/node/bindings.js';
await initializeBindings();
import fs from 'fs';
const log = [];
globalThis.__snarkyLog = log;
const maxVar = (x, seen = new Set()) => {
  if (x === null || typeof x !== 'object' || seen.has(x)) return -1;
  seen.add(x);
  if (Array.isArray(x)) {
    if (x[0] === 1 && typeof x[1] === 'number' && x.length === 2) return x[1];
    let m = -1; for (const y of x) m = Math.max(m, maxVar(y, seen)); return m;
  }
  return -1;
};
const short = (x, d = 0) => {
  if (typeof x === 'bigint') return x.toString();
  if (x === null || typeof x !== 'object') return typeof x === 'function' ? 'fn' : String(x);
  if (Array.isArray(x)) return d > 5 ? '[..]' : '[' + x.slice(0, 12).map(y => short(y, d + 1)).join(',') + (x.length > 12 ? `,..${x.length}` : '') + ']';
  return '{obj}';
};
for (const ns of ['field', 'gates', 'group', 'poseidon']) {
  for (const k of Object.keys(Snarky[ns])) {
    const f = Snarky[ns][k];
    Snarky[ns][k] = function (...args) {
      const r = f.apply(this, args);
      if (globalThis.__spikeMark) log.push({ f: `${ns}.${k}`, args: args.map(a => short(a)), max: maxVar(r) , rmax: maxVar(args), full: ns==='poseidon'||ns==='group'||k==='truncateToBits16' ? JSON.stringify(args,(k,v)=>typeof v==='bigint'?v.toString():v) : undefined});
      return r;
    };
  }
}
import { Types } from './node_modules/o1js/dist/node/bindings/mina-transaction/v1/types.js';
const toInput = Types.AccountUpdate.toInput;
const fv = (x) => (x?.value ?? x);
Types.AccountUpdate.toInput = function (au) {
  const r = toInput.call(this, au);
  if (globalThis.__spikeMark) {
    log.push({ f: 'AccountUpdate.toInput', fields: JSON.stringify(r.fields?.map((f) => fv(f)), (k, v) => (typeof v === 'bigint' ? v.toString() : v)), packed: JSON.stringify(r.packed?.map(([f, n]) => [fv(f), n]), (k, v) => (typeof v === 'bigint' ? v.toString() : v)) });
  }
  return r;
};
process.on('exit', () => fs.writeFileSync('/tmp/snarky-log.json', JSON.stringify(log)));
await import('./prove-local.mjs');
