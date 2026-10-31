import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AccountUpdate, Mina, PrivateKey, Signature, UInt64, fetchAccount, verify, type JsonProof } from 'o1js';
import { connectLightnet } from './lightnet.js';
import { Land, PROGRAM_VK_HASH } from './land-program.js';

// #36: `land` proved wholly in Rust, on a chain that checks every proof. o1js builds the command; the
// proof comes from `zk-prover`'s `prove_land` example, and o1js never proves `land` here.
const { sender, release } = await connectLightnet();
const FEE = 100_000_000;
const REPO = fileURLToPath(new URL('../..', import.meta.url));

type RustProof = { proof: string; programProof: string; publicInputFields: string[] };

/** Puts a proof in the account update, in place of the one o1js would make. */
function attachProof(update: AccountUpdate, proof: string) {
  update.authorization = { proof };
  update.lazyAuthorization = undefined;
}

function proveInRust(inputs: Record<string, string>): Promise<RustProof> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'cargo',
      ['run', '--quiet', '--release', '-p', 'zk-prover', '--example', 'prove_land'],
      { cwd: REPO, maxBuffer: 64 * 1024 * 1024 },
      (error, stdout, stderr) => (error ? reject(Error(`prove_land: ${stderr}`)) : resolve(JSON.parse(stdout)))
    );
    child.stdin!.end(JSON.stringify(inputs));
  });
}

describe('a Rust-proved land (proofs-on lightnet)', () => {
  const zkappKey = PrivateKey.random();
  const zkapp = new Land(zkappKey.toPublicKey());
  const payerKey = PrivateKey.random();
  let vk: { data: string; hash: { toString(): string } };

  /** Sends a signed command and waits for its block. */
  async function submit(tx: Mina.Transaction<boolean, false>, keys: PrivateKey[] = [sender.key]) {
    const sent = await tx.sign(keys).safeSend();
    if (sent.status === 'rejected') return { status: 'rejected', errors: sent.errors.map(String) };
    const done = await sent.safeWait();
    if (done.status === 'rejected') return { status: 'rejected', errors: done.errors.map(String) };
    return { status: 'included', errors: [] as string[] };
  }

  /** The command for `land(cumulative)` with the Rust proof of it in place of o1js's, and that proof. */
  async function rustProvedLand(cumulative: number) {
    await fetchAccount({ publicKey: zkapp.address });
    const landed = zkapp.landed.get();
    const amount = UInt64.from(cumulative);
    const sig = Signature.create(payerKey, amount.toFields());
    const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
      await zkapp.land(amount, sig);
    });
    const update = tx.transaction.accountUpdates.find((u) => u.publicKey.equals(zkapp.address).toBoolean())!;
    const lazy = update.lazyAuthorization;
    if (lazy?.kind !== 'lazy-proof') throw Error('o1js did not leave the proof to be made');
    const rust = await proveInRust({
      zkapp: zkapp.address.toBase58(),
      payer: payerKey.toPublicKey().toBase58(),
      cumulative: amount.toString(),
      sig: sig.toBase58(),
      landed: landed.toString(),
      blinding: lazy.blindingValue.toString(),
      vk: vk.data,
      vkHash: vk.hash.toString(),
    });
    // The hash Rust proved is the hash of the account update o1js built.
    const input = update.toPublicInput(tx.transaction);
    expect(rust.publicInputFields).toEqual([input.accountUpdate.toString(), input.calls.toString()]);
    return { tx, update, rust };
  }

  beforeAll(async () => {
    expect(Mina.getProofsEnabled()).toBe(true);
    ({ verificationKey: vk } = await Land.compile());
    expect(vk.hash.toString()).toBe(PROGRAM_VK_HASH);

    let tx = await Mina.transaction({ sender, fee: FEE }, async () => {
      AccountUpdate.fundNewAccount(sender);
      await zkapp.deploy();
    });
    await tx.prove();
    const deployed = await submit(tx, [sender.key, zkappKey]);
    expect(deployed).toEqual({ status: 'included', errors: [] });

    tx = await Mina.transaction({ sender, fee: FEE }, async () => {
      await zkapp.setup(payerKey.toPublicKey());
    });
    await tx.prove();
    const setUp = await submit(tx);
    expect(setUp).toEqual({ status: 'included', errors: [] });
  });
  afterAll(release);

  it('the chain applies it, and o1js verifies its proof under the compiled key', async () => {
    const { tx, update, rust } = await rustProvedLand(5);
    const json: JsonProof = {
      publicInput: rust.publicInputFields,
      publicOutput: [],
      maxProofsVerified: 0,
      proof: rust.programProof,
    };
    expect(await verify(json, vk.data)).toBe(true);

    attachProof(update, rust.proof);
    const outcome = await submit(tx);
    console.log('rust-proved land:', outcome);
    expect(outcome).toEqual({ status: 'included', errors: [] });
    await fetchAccount({ publicKey: zkapp.address });
    expect(zkapp.landed.get().toString()).toBe('5');
  });

  it('a second one applies on the state the first left', async () => {
    const { tx, update, rust } = await rustProvedLand(9);
    attachProof(update, rust.proof);
    const outcome = await submit(tx);
    console.log('second rust-proved land:', outcome);
    expect(outcome).toEqual({ status: 'included', errors: [] });
    await fetchAccount({ publicKey: zkapp.address });
    expect(zkapp.landed.get().toString()).toBe('9');
  });

  // What a proofs-off chain would accept (connector#1554).
  it('the chain refuses a real proof of another land', async () => {
    const other = await rustProvedLand(20);
    const { tx, update } = await rustProvedLand(21);
    attachProof(update, other.rust.proof);
    const outcome = await submit(tx);
    console.log('proof of another land:', outcome);
    expect(outcome.status).toBe('rejected');
    expect(outcome.errors.join('\n')).toMatch(/Invalid_proof/);
    await fetchAccount({ publicKey: zkapp.address });
    expect(zkapp.landed.get().toString()).toBe('9');
  });
});
