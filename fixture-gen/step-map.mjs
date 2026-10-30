// Write `land-step-map.txt` from o1js's `land` step witness: which o1js call site created each
// auxiliary variable, so a failing `zk-prover` witness test can name it. Each line is
// `start +count xN site`: N calls from `site` made `count` variables from `start` on; the gaps are
// Pickles' and snarky's own variables, `(OCaml)`.
// Usage: node step-map.mjs <dir>  (reads <dir>/w003_cs003.json, writes <dir>/land-step-map.txt)
import fs from 'fs';

const dir = process.argv[2];
const { external, trace } = JSON.parse(fs.readFileSync(`${dir}/w003_cs003.json`, 'utf8'));
// `name path:line:col)` -> `name:file.js:line`, for the first three frames. Frames in o1js's
// compiled `.cjs` bindings keep only their name.
const site = (s) => s.split(' < ').slice(0, 3).map((frame) => {
  const [name] = frame.split(' ');
  const m = frame.match(/([^/\s:]+\.m?js):(\d+)/);
  return `${name}:${m ? `${m[1]}:${m[2]}` : ''}`;
}).join(' < ');
const runs = [];
let next = 1;
const push = (start, count, calls, where) => {
  const last = runs[runs.length - 1];
  if (last && last.where === where && where !== '(OCaml)' && last.start + last.count === start) {
    last.count += count; last.calls += calls;
  } else runs.push({ start, count, calls, where });
};
for (const [start, count, s] of trace) {
  if (start > next) push(next, start - next, 1, '(OCaml)');
  push(start, count, 1, site(s));
  next = start + count;
}
if (external.length > next) push(next, external.length - next, 1, '(OCaml)');
fs.writeFileSync(`${dir}/land-step-map.txt`, runs.map((r) =>
  `${String(r.start).padStart(6)} +${String(r.count).padEnd(6)} x${String(r.calls).padEnd(3)} ${r.where}\n`).join(''));
