// A test harness for the vault on o1js's LocalBlockchain: fresh vaults with their own state key and
// off-chain mirror, and helpers that deposit, close, escape, finalize and reduce as a payer, the zk
// edge or a keeper would. Proofs are off unless a test turns them on.
import { AccountUpdate, Field, Mina, PrivateKey, PublicKey, Signature, UInt64, Unconstrained } from 'o1js';
import * as policy from './policy.js';
import { signClearance } from './clearance.js';
import { commitSecret } from './primitives.js';
import { PendingEscape, Vault, VaultAction, batchReducer } from './vault.js';
import { VaultMirror } from './vault-mirror.js';
import { WithdrawalKind, WithdrawalProgram, WithdrawalProof, WithdrawalPublic } from './withdrawal.js';
import { buildWithdrawal } from './withdrawal-sample.js';

type Local = Awaited<ReturnType<typeof Mina.LocalBlockchain>>;
type Account = Local['testAccounts'][number];
type Tx = Awaited<ReturnType<typeof Mina.transaction>>;
export type Note = { secret: bigint; size: bigint; depositTime: bigint };

/** The network's timestamp is that of the current slot's start. */
export const now = () => {
  const { genesisTimestamp, slotTime } = Mina.getNetworkConstants();
  return genesisTimestamp.toBigInt() + Mina.getNetworkState().globalSlotSinceGenesis.toBigint() * slotTime.toBigInt();
};
export const balanceOf = (pk: PublicKey) => Mina.getBalance(pk).toBigInt();

let nextSecret = 1000n;

export function vaultHarness(Local: Local) {
  const [payer, deployer, alice, bob, treasuryAccount] = Local.testAccounts;

  /** Moves the chain's clock forward by at least `ms`. */
  const advance = (ms: bigint) => {
    const slot = Mina.getNetworkConstants().slotTime.toBigInt();
    Local.incrementGlobalSlot(Number((ms + slot - 1n) / slot));
  };

  /** A fresh vault on the shared chain, with its own state key and an off-chain mirror. */
  async function freshVault({ setup = true } = {}) {
    const zkappKey = PrivateKey.random();
    const vault = new Vault(zkappKey.toPublicKey());
    const stateKey = PrivateKey.random();
    const treasury = treasuryAccount;
    const mirror = new VaultMirror();
    const send = async (tx: Tx, keys: PrivateKey[] = [], from: Account = payer) => {
      await tx.prove();
      await tx.sign([from.key, ...keys]).send();
    };
    const clearance = (pub: WithdrawalPublic, over: { key?: PrivateKey; nullifier?: Field; destination?: PublicKey } = {}) =>
      signClearance(over.key ?? stateKey, {
        stateKey: stateKey.toPublicKey(),
        nullifier: over.nullifier ?? pub.nullifier,
        destination: over.destination ?? pub.destination,
      });
    const closeTx = (proof: WithdrawalProof, c: Signature, from: Account = payer) =>
      Mina.transaction(from, async () => {
        await vault.mutualClose(proof, c, mirror.nullifiers.clone());
      });
    const escapeTx = (proof: WithdrawalProof, from: Account = payer) =>
      Mina.transaction(from, async () => {
        await vault.escape(proof, mirror.nullifiers.clone());
      });
    const finalizeTx = (escape: PendingEscape, from: Account = payer) =>
      Mina.transaction(from, async () => {
        await vault.finalize(escape, mirror.escapes.clone());
      });

    batchReducer.setContractInstance(vault);
    const tx = await Mina.transaction(deployer, async () => {
      AccountUpdate.fundNewAccount(deployer);
      await vault.deploy();
    });
    await tx.prove();
    await tx.sign([deployer.key, zkappKey]).send();

    const h = {
      vault, zkappKey, stateKey, treasury, mirror, send, clearance, closeTx, escapeTx, finalizeTx,
      async setup(keys = [zkappKey]) {
        await send(
          await Mina.transaction(payer, async () => {
            await vault.setup(stateKey.toPublicKey(), treasury);
          }),
          keys
        );
      },
      /** Deposits a note and returns its secret. */
      async deposit(size = policy.DEPOSIT_SIZES[0]): Promise<Note> {
        const secret = nextSecret++;
        const depositTime = now();
        const c = commitSecret(Field(secret));
        await send(
          await Mina.transaction(payer, async () => {
            await vault.deposit(c, UInt64.from(size), UInt64.from(depositTime));
          })
        );
        mirror.dispatched(VaultAction.deposit(c, UInt64.from(size), UInt64.from(depositTime)));
        return { secret, size, depositTime };
      },
      /** One reduce transaction per prepared batch, like a keeper would run. */
      async reduce() {
        batchReducer.setContractInstance(vault);
        for (const { batch, proof } of await batchReducer.prepareBatches()) {
          const t = now();
          const { witnesses, nullifiers, escapes } = mirror.nextReduce(t);
          await send(
            await Mina.transaction(payer, async () => {
              await vault.reduce(batch, proof, Unconstrained.from(witnesses), nullifiers, escapes, UInt64.from(t));
            })
          );
        }
      },
      /** Inputs and a proof of a withdrawal of `note`, made now against the mirror's tree. */
      async withdrawalProof(
        note: Note,
        o: {
          destination?: PublicKey; signed?: boolean; balance?: bigint; requestTime?: bigint; kind?: WithdrawalKind;
          key?: PrivateKey; conceded?: bigint; validUntil?: bigint;
        } = {}
      ) {
        const index = mirror.indexOf(commitSecret(Field(note.secret)));
        const kind = o.kind ?? WithdrawalKind.mutualClose;
        const { pub, priv } = buildWithdrawal(mirror.tree, {
          kind, secret: note.secret, index, size: note.size, depositTime: note.depositTime,
          requestTime: o.requestTime ?? now(), signed: o.signed ?? false, balance: o.balance ?? 0n,
          blinding: 99n, stateKey: o.key ?? stateKey, destination: o.destination ?? alice,
          conceded: o.conceded, validUntil: o.validUntil,
        });
        const method = {
          [WithdrawalKind.mutualClose]: WithdrawalProgram.mutualClose,
          [WithdrawalKind.escape]: WithdrawalProgram.escape,
          [WithdrawalKind.ownership]: WithdrawalProgram.ownership,
        }[kind];
        const { proof } = await method(pub, priv);
        return proof;
      },
      /** Sends a mutual close and records its action in the mirror. */
      async close(proof: WithdrawalProof, c = clearance(proof.publicInput)) {
        await send(await closeTx(proof, c));
        mirror.dispatched(VaultAction.mutualClose(proof.publicInput));
      },
      /** Sends an escape and records its action in the mirror. */
      async escape(proof: WithdrawalProof, from: Account = payer) {
        await send(await escapeTx(proof, from), [], from);
        mirror.dispatched(VaultAction.escape(proof.publicInput));
      },
      /** Sends a finalize of the pending escape at `nullifier` and records its action in the mirror. */
      async finalize(nullifier: Field, from: Account = payer) {
        const escape = mirror.pendingEscape(nullifier);
        if (!escape) throw Error('no pending escape at that nullifier in the mirror');
        await send(await finalizeTx(escape, from), [], from);
        mirror.dispatched(VaultAction.finalize(escape));
      },
    };
    if (setup) await h.setup();
    return h;
  }

  return { payer, deployer, alice, bob, treasuryAccount, advance, freshVault };
}
