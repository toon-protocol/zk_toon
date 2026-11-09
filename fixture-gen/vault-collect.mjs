// Turns the dumps of `vault-fixtures.ts` (the `compile`, `main` and `recursive` directories under <work>) into
// the committed fixtures: for each case, the step circuit, the wrap circuit, o1js's step proof with its public
// input and the wrap witness (reduced to what the Rust tests read); and the verification keys.
// Usage: node vault-collect.mjs <work dir> <fixtures dir>
import fs from 'node:fs';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

const [work, fixtures] = process.argv.slice(2);
const die = (m) => { console.error(`vault-collect: ${m}`); process.exit(1); };
const pad = (n) => String(n).padStart(3, '0');
const CIRCUIT_FILES = ['gates.json', 'internal_vars.bin', 'rows_rev.bin'];
const gz = (file, data) => fs.writeFileSync(`${fixtures}/${file}.gz`, zlib.gzipSync(data, { level: 9, mtime: 0 }));

// A circuit's identity is its content, so the same circuit dumped by two processes is one circuit.
const digest = (dir, id) => {
  const h = crypto.createHash('sha256');
  for (const f of CIRCUIT_FILES) h.update(fs.readFileSync(`${dir}/cs${pad(id)}_${f}`));
  return h.digest('hex');
};
const canonical = new Set();
for (const f of fs.readdirSync(`${work}/compile`)) {
  const m = /^cs(\d+)_gates\.json$/.exec(f);
  if (m) canonical.add(digest(`${work}/compile`, Number(m[1])));
}
if (canonical.size === 0) die('the compile process dumped no circuits');

/** circuit name -> digest, to check that two cases that share a circuit really do, and two that don't, don't. */
const written = new Map();
const circuit = (name, dir, id) => {
  const d = digest(dir, id);
  if (!canonical.has(d)) die(`${name}: its circuit is not among the compile process's`);
  if (written.has(name)) {
    if (written.get(name) !== d) die(`${name}: two cases give different circuits`);
    return;
  }
  for (const [other, od] of written) if (od === d) die(`${name} and ${other} share a circuit`);
  written.set(name, d);
  for (const f of CIRCUIT_FILES) gz(`${name}_${f}`, fs.readFileSync(`${dir}/cs${pad(id)}_${f}`));
};

const find = (dir, prefix) => {
  const found = fs.readdirSync(dir).filter((f) => f.startsWith(prefix));
  if (found.length !== 1) die(`${dir}: expected one ${prefix}*, found ${found.length}`);
  return found[0];
};
const circuitOf = (file) => Number(/_cs(\d+)\.json$/.exec(file)[1]);

// case: [fixture prefix, step circuit] for each proof o1js made in it (the wrap circuit is `wrapName`'s)
const NAMES = {
  setup: [['vault_setup', 'vault_setup']],
  deposit: [['vault_deposit', 'vault_deposit']],
  reduce: [['vault_reduce', 'vault_reduce']],
  mutualClose: [['vault_mutualClose', 'vault_mutualClose']],
  escape: [['vault_escape', 'vault_escape']],
  defeat: [['vault_defeat', 'vault_defeat']],
  raise: [['vault_raise', 'vault_raise']],
  finalize: [['vault_finalize', 'vault_finalize']],
  sweepExpired: [['vault_sweepExpired', 'vault_sweepExpired']],
  reduceRecursive: [['vault_reduce_recursive', 'vault_reduce']],
  // `provableBatches` proves the last chunk first, from the dummy, then the one before from it.
  chunks: [['chunk_dummy', 'chunk'], ['chunk_chained', 'chunk']],
};
const wrapName = (prefix) => (prefix.startsWith('chunk') ? 'chunk_wrap' : 'vault_wrap');
const seen = new Set();
for (const proc of ['main', 'recursive']) {
  const dir = `${work}/${proc}`;
  for (const c of JSON.parse(fs.readFileSync(`${dir}/manifest.json`, 'utf8'))) {
    const names = NAMES[c.name] ?? die(`unknown case ${c.name}`);
    seen.add(c.name);
    const [nProofs, nWitnesses] = [c.proofs[1] - c.proofs[0] + 1, c.witnesses[1] - c.witnesses[0] + 1];
    if (nProofs !== names.length || nWitnesses !== 2 * names.length) {
      die(`${c.name}: ${nProofs} step proofs and ${nWitnesses} witnesses, expected ${names.length} and ${2 * names.length}`);
    }
    names.forEach(([prefix, stepName], i) => {
      // Each proof is a step witness, o1js's step proof, then the wrap witness for it.
      const stepFile = find(dir, `w${pad(c.witnesses[0] + 2 * i)}_`);
      const wrapFile = find(dir, `w${pad(c.witnesses[0] + 2 * i + 1)}_`);
      const step = JSON.parse(fs.readFileSync(`${dir}/${stepFile}`, 'utf8'));
      const wrap = JSON.parse(fs.readFileSync(`${dir}/${wrapFile}`, 'utf8'));
      if (step.public_input_size >= wrap.public_input_size) die(`${prefix}: ${stepFile}, ${wrapFile} are not a step and its wrap witness`);
      circuit(stepName, dir, circuitOf(stepFile));
      circuit(wrapName(prefix), dir, circuitOf(wrapFile));
      gz(`${prefix}_stepproof.b64`, fs.readFileSync(`${dir}/stepproof${pad(c.proofs[0] + i)}.b64`));
      // A step proof's public input is not in its dump, but o1js's step witness starts with it.
      gz(`${prefix}_stepproof_public.json`, JSON.stringify(step.external.slice(0, step.public_input_size)));
      gz(`${prefix}_wrap_witness.json`, JSON.stringify({ public_input_size: wrap.public_input_size, external: wrap.external }));
    });
  }
}
for (const name of Object.keys(NAMES)) if (!seen.has(name)) die(`no process proved ${name}`);

const keys = JSON.parse(fs.readFileSync(`${work}/compile/keys.json`, 'utf8'));
for (const proc of ['main', 'recursive']) {
  // The keys a proving process loaded from the cache are the ones the compile process made.
  if (JSON.stringify(JSON.parse(fs.readFileSync(`${work}/${proc}/keys.json`, 'utf8'))) !== JSON.stringify(keys)) die(`${proc} compiled other keys`);
}
gz('vault_keys.json', JSON.stringify(keys));
console.log(`wrote ${seen.size} cases, ${written.size} circuits`);
