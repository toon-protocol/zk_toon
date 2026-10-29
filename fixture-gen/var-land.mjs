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
const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);
// TOY KEYS: small fixed scalars so the fixtures are reproducible. Never use them for anything else.
const fee = Mina.TestPublicKey(PrivateKey.fromBigInt(1003n));
Local.addAccount(fee, '1000000000000');
const zkKey = PrivateKey.fromBigInt(BigInt(process.env.ZK||1001)), zkAddr = zkKey.toPublicKey();
const payerKey = PrivateKey.fromBigInt(BigInt(process.env.PAYER||1002)), payer = payerKey.toPublicKey();
const zk = new Land(zkAddr);
const { verificationKey } = await Land.compile();
let tx = await Mina.transaction(fee, async () => { AccountUpdate.fundNewAccount(fee); await zk.deploy(); });
await tx.sign([fee.key, zkKey]).send();
tx = await Mina.transaction(fee, async () => { await zk.setup(payer); });
await tx.prove(); await tx.sign([fee.key]).send();
const cumulative = UInt64.from(BigInt(process.env.CUM||5));
const sig = Signature.create(payerKey, cumulative.toFields());
tx = await Mina.transaction(fee, async () => { await zk.land(cumulative, sig); });
globalThis.__spikeTrace = []; globalThis.__spikeMark = true;
fs.writeFileSync(`${OUT}/land.unproved.tx.json`, tx.toJSON());
const t = Date.now();
await tx.prove();
console.log('land prove ms', Date.now() - t);
fs.writeFileSync(`${OUT}/land.proved.tx.json`, tx.toJSON());
await tx.sign([fee.key]).send();
console.log('landed', zk.landed.get().toString(), 'vk', verificationKey.hash.toString());
fs.writeFileSync(`${OUT}/inputs.json`, JSON.stringify({ zkapp: zkAddr.toBase58(), payer: payer.toBase58(), cumulative: '5', sig: sig.toBase58(), vk: verificationKey.data, vkHash: verificationKey.hash.toString() }));
