// Turns the dumps of `vault-fixtures.ts` (the `compile`, `main` and `recursive` directories under <work>) into
// the committed fixtures: for each case, the step circuit, the wrap circuit, o1js's step proof with its public
// input and the wrap witness (reduced to what the Rust tests read), the zkApp public input of the call and, for a
// method that verifies a proof, that proof (`_previous.json`, with the name of its program's key); o1js's step witness
// (`_step_witness.json`), a map of the o1js call site of each of its variables (`_step_map.txt`) and the inputs a Rust
// builder of it needs (`_inputs.json`); and the verification keys.
// A step witness whose gzip is over `MAX_GZ` is committed as the hashes of its blocks of `BLOCK` values instead
// (`_step_witness_blocks.json`). With STEP_WITNESS_DIR set, every full step witness is also written there.
// Usage: node vault-collect.mjs <work dir> <fixtures dir>
import fs from 'node:fs';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { stepMap } from './step-map.mjs';

const [work, fixtures] = process.argv.slice(2);
const die = (m) => { console.error(`vault-collect: ${m}`); process.exit(1); };
const pad = (n) => String(n).padStart(3, '0');
const CIRCUIT_FILES = ['gates.json', 'internal_vars.bin', 'rows_rev.bin'];
const MAX_GZ = Number(process.env.MAX_STEP_WITNESS_GZ ?? 50 * 1024 * 1024);
const BLOCK = 1024;
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
// The cases whose method verifies a proof, and the key of the program that made it (`vault_keys.json`).
const PREVIOUS = {
  reduce: 'vaultReducer', reduceRecursive: 'vaultReducer', mutualClose: 'withdrawal', escape: 'withdrawal',
  defeat: 'request', raise: 'request',
};
/** The step witness as the toy's (`{ public_input_size, external }`), or its block hashes if too large. */
const stepWitness = (prefix, step) => {
  const witness = JSON.stringify({ public_input_size: step.public_input_size, external: step.external });
  if (process.env.STEP_WITNESS_DIR) fs.writeFileSync(`${process.env.STEP_WITNESS_DIR}/${prefix}_step_witness.json`, witness);
  const packed = zlib.gzipSync(witness, { level: 9, mtime: 0 });
  // Only one of the two forms stays.
  fs.rmSync(`${fixtures}/${prefix}_step_witness.json.gz`, { force: true });
  fs.rmSync(`${fixtures}/${prefix}_step_witness_blocks.json.gz`, { force: true });
  if (packed.length <= MAX_GZ) {
    fs.writeFileSync(`${fixtures}/${prefix}_step_witness.json.gz`, packed);
    return;
  }
  // The hash of block k is the sha256 of its values' decimal strings, each followed by a newline.
  const sha256 = [];
  for (let i = 0; i < step.external.length; i += BLOCK) {
    sha256.push(crypto.createHash('sha256').update(step.external.slice(i, i + BLOCK).map((v) => `${v}\n`).join('')).digest('hex'));
  }
  gz(`${prefix}_step_witness_blocks.json`, JSON.stringify({ public_input_size: step.public_input_size, length: step.external.length, block: BLOCK, sha256 }));
  console.log(`${prefix}: the step witness is ${packed.length} bytes gzipped, over the limit: committed its block hashes`);
};
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
    // A vault method's call: the public input of its zkApp proof, and the proof its method verified.
    if (c.name !== 'chunks') {
      const [prefix] = names[0];
      gz(`${prefix}_zkapp_public.json`, fs.readFileSync(`${dir}/${c.name}_zkapp_public.json`));
      if (PREVIOUS[c.name]) {
        const previous = JSON.parse(fs.readFileSync(`${dir}/${c.name}_previous.json`, 'utf8'));
        gz(`${prefix}_previous.json`, JSON.stringify({ ...previous, key: PREVIOUS[c.name] }));
      } else if (fs.existsSync(`${dir}/${c.name}_previous.json`)) die(`${c.name} verifies no proof`);
    }
    // The chunks: each `proveChunk` call's proof is `<prefix>_proof.json` (its public input and output, which o1js's
    // `verify` reads), and the proof it verified `<prefix>_previous.json`, under the reducer's key.
    let calls;
    if (c.name === 'chunks') {
      calls = JSON.parse(fs.readFileSync(`${dir}/chunks_calls.json`, 'utf8'));
      if (calls.length !== names.length) die(`chunks: ${calls.length} proveChunk calls, expected ${names.length}`);
      if (JSON.stringify(calls[1].previous) !== JSON.stringify(calls[0].proof)) die('chunks: the second call did not verify the first call\'s proof');
      names.forEach(([prefix], i) => {
        gz(`${prefix}_previous.json`, JSON.stringify({ ...calls[i].previous, key: 'vaultReducer' }));
        gz(`${prefix}_proof.json`, JSON.stringify(calls[i].proof));
      });
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
      // The step witness: its values (the public input first), the o1js call site of each variable, and the inputs.
      const inputs = c.name === 'chunks' ? calls[i].inputs : JSON.parse(fs.readFileSync(`${dir}/${c.name}_inputs.json`, 'utf8'));
      // The blinding of the call's `callData` is witnessed, and o1js's trace says where.
      if (inputs.blinding !== undefined && !step.external.slice(step.public_input_size).includes(inputs.blinding)) {
        die(`${prefix}: the step witness does not hold the blinding ${inputs.blinding}`);
      }
      gz(`${prefix}_inputs.json`, JSON.stringify(inputs));
      gz(`${prefix}_step_map.txt`, stepMap(step));
      stepWitness(prefix, step);
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
