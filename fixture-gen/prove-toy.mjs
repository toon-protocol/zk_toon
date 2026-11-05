// Prove the toy zkApp's two methods on a LocalBlockchain with fixed keys, dumping o1js's step and wrap
// circuits and witnesses (SPIKE_DUMP) as the Rust wrap prover's reference. See `toy.mjs`.
import { Mina, PrivateKey, AccountUpdate, Field } from 'o1js';
import { Inner, InnerProof, Outer } from './toy.mjs';
import fs from 'fs';
import { Fp } from './node_modules/o1js/dist/node/bindings/crypto/finite-field.js';
let blinding = 0n;
Fp.random = () => ++blinding;
const OUT = process.env.SPIKE_DUMP;
const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);
// TOY KEYS: small fixed scalars so the fixtures are reproducible. Never use them for anything else.
const fee = Mina.TestPublicKey(PrivateKey.fromBigInt(2003n));
Local.addAccount(fee, '1000000000000');
const zkKey = PrivateKey.fromBigInt(2001n), zkAddr = zkKey.toPublicKey();
const zk = new Outer(zkAddr);
const { verificationKey: innerVk } = await Inner.compile();
const { verificationKey } = await Outer.compile();
const { proof: innerProof } = await Inner.base(Field(49), Field(7));
fs.writeFileSync(`${OUT}/inner_proof.json`, JSON.stringify(innerProof.toJSON()));
let tx = await Mina.transaction(fee, async () => { AccountUpdate.fundNewAccount(fee); await zk.deploy(); });
await tx.sign([fee.key, zkKey]).send();
// The public input o1js proves a method against: the account update's hash and its calls' hash.
const publicInput = (tx) => tx.transaction.accountUpdates.find((a) => a.publicKey.toBase58() === zkAddr.toBase58()).toPublicInput(tx.transaction);
// What the Rust verifier and o1js's `verify` read: the proof o1js attached to the zkApp's account update.
const writeProof = (method, tx, input, max) => {
  const proof = JSON.parse(tx.toJSON()).accountUpdates.find((a) => a.body.publicKey === zkAddr.toBase58()).authorization.proof;
  fs.writeFileSync(`${OUT}/${method}_proof.json`, JSON.stringify({
    program: 'toy', maxProofsVerified: max,
    verificationKey: { data: verificationKey.data, hash: verificationKey.hash.toString() },
    proof, publicInputFields: [input.accountUpdate.toString(), input.calls.toString()], publicOutputFields: [] }));
};
// `maxProofsVerified` is the program's: 1, for the `plain` method too.
tx = await Mina.transaction(fee, async () => { await zk.plain(Field(3)); });
let input = publicInput(tx);
await tx.prove();
writeProof('plain', tx, input, 1);
await tx.sign([fee.key]).send();
tx = await Mina.transaction(fee, async () => { await zk.recurse(Field(49), innerProof); });
input = publicInput(tx);
await tx.prove();
writeProof('recurse', tx, input, 1);
await tx.sign([fee.key]).send();
fs.writeFileSync(`${OUT}/inputs.json`, JSON.stringify({
  zkapp: zkAddr.toBase58(), vk: verificationKey.data, vkHash: verificationKey.hash.toString(),
  innerVk: innerVk.data, innerVkHash: innerVk.hash.toString(), innerPublicInput: '49',
}));
