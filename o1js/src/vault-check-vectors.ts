// `npm run vault-check-vectors`: writes test-vectors/vault-check.json, snapshots of vaults on o1js's local chain
// and what the check answers on each (`refuses` empty is a pass). With proofs off every vault carries o1js's dummy
// key, so `codeHash` is that key's hash; the permissions name o1js's transaction version.
import { writeFileSync } from 'node:fs';
import { Field, Mina, PublicKey, UInt64 } from 'o1js';
import * as policy from './policy.js';
import { RequestProgram } from './request.js';
import { batchReducer } from './vault.js';
import { chainReader, judgeVault, readVault } from './vault-check.js';
import { LOOSENED, dispatch, forged, phantomDeposit } from './vault-forge.js';
import { vaultHarness } from './vault-harness.js';
import { WithdrawalProgram } from './withdrawal.js';

const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
WithdrawalProgram.setProofsEnabled(false);
RequestProgram.setProofsEnabled(false);
await batchReducer.compile();
const { deployer, freshVault, treasuryAccount: treasury } = vaultHarness(Local);
const reader = chainReader({ localChain: true });

const honest = await freshVault();
const codeHash = Mina.getAccount(honest.vault.address).zkapp!.verificationKey!.hash.toString();
const used = await freshVault();
await used.deposit(policy.DEPOSIT_SIZES[0]);
await used.deposit(policy.DEPOSIT_SIZES[1]);
await used.reduce();
await used.deposit(policy.DEPOSIT_SIZES[0]);

const usedSnapshot = await readVault(used.vault.address, reader);
const honestAndLoosened: [string, Promise<PublicKey> | PublicKey, string?][] = [
  ['a fresh vault', honest.vault.address],
  ['a vault with reduced and pending deposits', used.vault.address],
  ['another code hash', honest.vault.address, '12345'],
  ['send loosened', forged({ deployer, treasury }, { permissions: { send: LOOSENED.send() } }).then((v) => v.address)],
];
const cases = [];
for (const [name, address, hash] of honestAndLoosened) {
  const snapshot = await readVault(await address, reader);
  cases.push({ name, codeHash: hash ?? codeHash, snapshot });
}
const prefilled: [string, Parameters<typeof forged>[1]][] = [
  ['a short challenge window', { write: (v) => v.challengeWindow.set(UInt64.from(1)) }],
  ['a prefilled note root', { write: (v) => v.noteRoot.set(Field(123)) }],
  ['a fake deposit no balance backs', { write: (v) => dispatch(v, phantomDeposit()) }],
];
for (const [name, o] of prefilled) {
  const v = await forged({ deployer, treasury }, o);
  cases.push({ name, codeHash, snapshot: await readVault(v.address, reader) });
}
cases.push({ name: 'an archive that left out an action', codeHash, snapshot: { ...usedSnapshot, actions: usedSnapshot.actions.slice(1) } });

const out = cases.map((c) => {
  const v = judgeVault(c.snapshot, c.codeHash);
  return { ...c, refuses: v.pass ? [] : v.refusals.map((r) => r.check) };
});
const path = new URL('../../test-vectors/vault-check.json', import.meta.url);
writeFileSync(path, `${JSON.stringify({ cases: out }, null, 2)}\n`);
for (const c of out) console.log(`${c.name}: ${c.refuses.join(', ') || 'pass'}`);
console.log(`wrote ${path.pathname}`);
process.exit(0);
