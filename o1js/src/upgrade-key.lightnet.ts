// The upgrade key's threshold signature on a node (#123): a registered vault's delegation and a key install on a
// stand-in account, each prepared and attached by the transaction builder and signed 2-of-3 in Rust
// (`upgrade-key`'s `threshold_sign` example). The gate doesn't run it.
//
// The registry needs the whole key's signature once, when it deploys the vault, so the script holds the two keys and the
// Rust side splits each, as the tests do. A real upgrade key has no whole key to hold (ADR 0012).
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AccountUpdate, Mina, Permissions, PrivateKey, PublicKey, Types, UInt64, ZkProgram, fetchAccount } from 'o1js';
import { ARCHIVE, MINA, connectLightnet, lightnetLanding } from './lightnet.js';
import { createBuilder } from './tx-builder.js';
import { Uri, type Registry, registryDeployTx, vaultKey as vaultKeyOf } from './vault-registry.js';
import { VAULT_URI } from './vault.js';

const FEE = 100_000_000;
const REPO = fileURLToPath(new URL('../..', import.meta.url));
const { sender, release } = await connectLightnet();
const { land, landAt } = lightnetLanding(MINA, sender);
const builder = await createBuilder({ local: false, proofs: true, mina: MINA, archive: ARCHIVE });

/** One builder operation; a failure answer fails the test. */
async function ask(op: string, params: object) {
  const answer = JSON.parse(await builder.handle(JSON.stringify({ id: 1, op, params })));
  if (!answer.ok) throw Error(`${op}: ${answer.error.kind}: ${answer.error.message}`);
  return answer.result;
}

/** The signature of two of three holders of `key`, split from it in Rust, over `commitment` for `network`. */
function thresholdSign(key: PrivateKey, commitment: string, network: string): Promise<{ r: string; s: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'cargo',
      ['run', '--quiet', '--release', '-p', 'upgrade-key', '--features', 'test-utils', '--example', 'threshold_sign'],
      { cwd: REPO },
      (error, stdout, stderr) => (error ? reject(Error(`threshold_sign: ${stderr}`)) : resolve(JSON.parse(stdout)))
    );
    child.stdin!.end(JSON.stringify({ secretKey: key.toBase58(), commitment, network }));
  });
}

/** Sends a command the builder signed and waits for its block; answers why it did not apply, or nothing. */
async function send(zkappCommand: unknown): Promise<string | undefined> {
  const sent = await Mina.Transaction.fromJSON(zkappCommand as never).safeSend();
  if (sent.status === 'rejected') return sent.errors.map(String).join('; ');
  const done = await sent.safeWait({ maxAttempts: 60, interval: 5_000 });
  return done.status === 'rejected' ? done.errors.map(String).join('; ') : undefined;
}

const account = async (address: PublicKey) => {
  const { account } = await fetchAccount({ publicKey: address });
  return account ? Types.Account.toJSON(account) : undefined;
};

describe('the upgrade key on a proofs-on lightnet', () => {
  const payer = { privateKey: sender.key.toBase58(), fee: String(FEE) };
  const payerAddress = { publicKey: sender.toBase58(), fee: String(FEE) };
  const vaultKey = PrivateKey.random();
  const standInKey = PrivateKey.random();
  let registry: Registry;

  beforeAll(async () => {
    expect(Mina.getProofsEnabled()).toBe(true);
    const registryKey = PrivateKey.random();
    let deployed: Awaited<ReturnType<typeof registryDeployTx>> | undefined;
    await land('registry deploy', async () => {
      deployed = await registryDeployTx({ sender, fee: FEE }, registryKey);
      await deployed.tx.prove();
      return deployed.tx;
    }, [registryKey]);
    registry = deployed!.registry;

    await landAt('register', async (slot) => {
      await fetchAccount({ publicKey: registry.address });
      const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
        AccountUpdate.fundNewAccount(sender);
        await registry.register(vaultKey.toPublicKey(), await vaultKeyOf(), UInt64.from(slot), Uri.from(VAULT_URI));
      });
      await tx.prove();
      return tx;
    }, 4n, [vaultKey]);

    // The stand-in: an account whose `setVerificationKey` is `signature`.
    await land('stand-in', async () =>
      Mina.transaction({ sender, fee: FEE }, async () => {
        AccountUpdate.fundNewAccount(sender);
        const update = AccountUpdate.createSigned(standInKey.toPublicKey());
        update.account.permissions.set({ ...Permissions.default(), setVerificationKey: Permissions.VerificationKey.signature() });
      }), [standInKey]);
  });
  afterAll(release);

  it('a delegation of the registered vault, signed 2-of-3, changes its delegate', async () => {
    const vault = vaultKey.toPublicKey();
    const delegate = PrivateKey.random().toPublicKey();
    const prepared = await ask('prepareDelegation', { vault: vault.toBase58(), delegate: delegate.toBase58(), feePayer: payerAddress, network: 'testnet' });
    const signature = await thresholdSign(vaultKey, prepared.fullCommitment, 'testnet');
    const { zkappCommand } = await ask('attachDelegation', { zkappCommand: prepared.zkappCommand, signature, feePayer: payer, network: 'testnet' });
    const failure = await send(zkappCommand);
    console.log('delegation:', failure ?? 'applied');
    expect(failure).toBeUndefined();
    expect((await account(vault))?.delegate).toBe(delegate.toBase58());
  });

  it('a key install on the stand-in, signed 2-of-3, installs the key', async () => {
    const standIn = standInKey.toPublicKey();
    // A key o1js compiled, other than the vault's.
    const Program = ZkProgram({ name: 'InstalledKey', methods: { noop: { privateInputs: [], async method() {} } } });
    const { verificationKey } = await Program.compile();
    const key = { data: verificationKey.data, hash: verificationKey.hash.toString() };
    const prepared = await ask('prepareKeyInstall', { account: standIn.toBase58(), verificationKey: key, feePayer: payerAddress, network: 'testnet' });
    const signature = await thresholdSign(standInKey, prepared.fullCommitment, 'testnet');
    const { zkappCommand } = await ask('attachKeyInstall', { zkappCommand: prepared.zkappCommand, signature, feePayer: payer, network: 'testnet' });
    const failure = await send(zkappCommand);
    console.log('key install:', failure ?? 'applied');
    expect(failure).toBeUndefined();
    expect((await account(standIn))?.zkapp?.verificationKey?.hash).toBe(key.hash);
  });
});
