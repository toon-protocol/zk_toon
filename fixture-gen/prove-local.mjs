// Prove `land` on a LocalBlockchain with fixed keys, dumping o1js's
// step/wrap witnesses (SPIKE_DUMP) and the transaction, as the Rust prover's reference.
import { Mina, PrivateKey, AccountUpdate, UInt64, Signature } from 'o1js';
import { Land } from './land.mjs';
import fs from 'fs';
import { Fp } from './node_modules/o1js/dist/node/bindings/crypto/finite-field.js';
// o1js blinds each account update's callData with a random field element; count instead, so a rerun is byte-identical.
let blinding = 0n;
Fp.random = () => ++blinding;
const OUT = process.env.SPIKE_DUMP;
// The public input o1js proves a method against: the account update's hash and its calls' hash.
function publicInput(tx) {
  const au = tx.transaction.accountUpdates.find((a) => a.publicKey.toBase58() === zkAddr.toBase58());
  return au.toPublicInput(tx.transaction);
}
// What the Rust verifier checks: the proof o1js attached to the zkApp's account update, its public
// input and the program's verification key.
function writeProof(method, tx, input) {
  const proof = JSON.parse(tx.toJSON()).accountUpdates.find((a) => a.body.publicKey === zkAddr.toBase58()).authorization.proof;
  fs.writeFileSync(`${OUT}/${method}_proof.json`, JSON.stringify({
    program: 'land',
    maxProofsVerified: 0,
    verificationKey: { data: verificationKey.data, hash: verificationKey.hash.toString() },
    proof,
    publicInputFields: [input.accountUpdate.toString(), input.calls.toString()],
    publicOutputFields: [],
  }));
}
const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);
// TOY KEYS: small fixed scalars so the fixtures are reproducible. Never use them for anything else.
const fee = Mina.TestPublicKey(PrivateKey.fromBigInt(1003n));
Local.addAccount(fee, '1000000000000');
const zkKey = PrivateKey.fromBigInt(1001n), zkAddr = zkKey.toPublicKey();
const payerKey = PrivateKey.fromBigInt(1002n), payer = payerKey.toPublicKey();
const zk = new Land(zkAddr);
const { verificationKey } = await Land.compile();
let tx = await Mina.transaction(fee, async () => { AccountUpdate.fundNewAccount(fee); await zk.deploy(); });
await tx.sign([fee.key, zkKey]).send();
tx = await Mina.transaction(fee, async () => { await zk.setup(payer); });
const setupInput = publicInput(tx);
await tx.prove();
writeProof('setup', tx, setupInput);
await tx.sign([fee.key]).send();
const cumulative = UInt64.from(5);
const sig = Signature.create(payerKey, cumulative.toFields());
tx = await Mina.transaction(fee, async () => { await zk.land(cumulative, sig); });
globalThis.__spikeTrace = []; globalThis.__spikeMark = true;
fs.writeFileSync(`${OUT}/land.unproved.tx.json`, tx.toJSON());
const landInput = publicInput(tx);
const t = Date.now();
await tx.prove();
writeProof('land', tx, landInput);
console.log('land prove ms', Date.now() - t);
fs.writeFileSync(`${OUT}/land.proved.tx.json`, tx.toJSON());
await tx.sign([fee.key]).send();
console.log('landed', zk.landed.get().toString(), 'vk', verificationKey.hash.toString());
fs.writeFileSync(`${OUT}/inputs.json`, JSON.stringify({ zkapp: zkAddr.toBase58(), payer: payer.toBase58(), cumulative: '5', sig: sig.toBase58(), vk: verificationKey.data, vkHash: verificationKey.hash.toString() }));
