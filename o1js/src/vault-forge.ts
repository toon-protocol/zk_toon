// Forged vaults for testing the vault check (#75, ADR 0008): what a deployer can really make, with the honest code
// hash and with state, actions and permissions written under the upgrade key's signature before it locks the account.
import { AccountUpdate, Field, Mina, Permissions, PrivateKey, PublicKey, UInt32, UInt64 } from 'o1js';
import { NoteTree } from './note-tree.js';
import * as policy from './policy.js';
import { commitSecret } from './primitives.js';
import { RootRing, VAULT_URI, Vault, VaultAction } from './vault.js';
import { now } from './vault-harness.js';
import type { VaultReader } from './vault-check.js';
import { WithdrawalKind, WithdrawalPublic } from './withdrawal.js';

const [SMALL] = policy.DEPOSIT_SIZES;
type Local = Awaited<ReturnType<typeof Mina.LocalBlockchain>>;
type Account = Local['testAccounts'][number];

const LOOSE = {
  ...Permissions.default(), editState: Permissions.signature(), editActionState: Permissions.signature(), send: Permissions.signature(),
  setPermissions: Permissions.signature(), setTiming: Permissions.signature(),
};
/** ADR 0006's table, written out again: the deploy and the check must both agree with it. */
export const LOCKED = () => ({
  editState: Permissions.proof(), send: Permissions.proof(), editActionState: Permissions.proof(), access: Permissions.none(),
  receive: Permissions.none(), setVerificationKey: Permissions.VerificationKey.impossibleDuringCurrentVersion(),
  setPermissions: Permissions.impossible(), setTiming: Permissions.impossible(), incrementNonce: Permissions.impossible(),
  setZkappUri: Permissions.impossible(), setVotingFor: Permissions.impossible(), setTokenSymbol: Permissions.impossible(),
  setDelegate: Permissions.signature(),
});
/** A value for each permission other than ADR 0006's. */
export const LOOSENED: { [K in keyof ReturnType<typeof LOCKED>]: () => ReturnType<typeof LOCKED>[K] } = {
  editState: Permissions.signature, send: Permissions.signature, editActionState: Permissions.signature, access: Permissions.proof,
  receive: Permissions.proof, setVerificationKey: Permissions.VerificationKey.signature, setPermissions: Permissions.signature,
  setTiming: Permissions.signature, incrementNonce: Permissions.signature, setZkappUri: Permissions.signature,
  setVotingFor: Permissions.signature, setTokenSymbol: Permissions.signature, setDelegate: Permissions.impossible,
};

const withActions = (update: AccountUpdate, actions: VaultAction[]) => {
  for (const a of actions) update.body.actions = AccountUpdate.Actions.pushEvent(update.body.actions, VaultAction.toFields(a));
};
/** Writes `actions` to the vault's stream under the upgrade key's signature, an account update each, as its methods do. */
export const dispatch = (vault: Vault, ...actions: VaultAction[]) => {
  for (const a of actions) withActions(AccountUpdate.createSigned(vault.address), [a]);
};
/** Writes `actions` to the vault's stream as one account update, which no method does. */
export const dispatchTogether = (vault: Vault, ...actions: VaultAction[]) => withActions(vault.self, actions);

/**
 * A vault its deployer forges: `init` and `deploy` run as published, `write` changes what it likes under the
 * upgrade key's signature, then `setup`'s fields are written and the account is locked with `permissions`.
 */
export async function forged({ deployer, treasury }: { deployer: Account; treasury: PublicKey }, o: {
  write?: (v: Vault) => void; permissions?: Partial<ReturnType<typeof LOCKED>>; timed?: boolean; stateKey?: PublicKey;
} = {}) {
  const key = PrivateKey.random();
  const vault = new Vault(key.toPublicKey());
  const signed = async (body: () => void | Promise<void>) => {
    const tx = await Mina.transaction(deployer, async () => { await body(); });
    await (await tx.sign([deployer.key, key]).send()).wait();
  };
  await signed(async () => {
    AccountUpdate.fundNewAccount(deployer);
    await vault.deploy({ zkappUri: VAULT_URI });
    vault.self.account.permissions.set(LOOSE);
  });
  // Outside a method, `self` joins the transaction only when attached: first, so the updates `body` adds count its nonce.
  const write = (body: () => void) => signed(() => {
    vault.requireSignature();
    AccountUpdate.attachToTransaction(vault.self);
    body();
  });
  // A minimum balance needs a balance to hold it.
  if (o.timed) await signed(() => { AccountUpdate.createSigned(deployer).send({ to: vault.address, amount: UInt64.from(1) }); });
  await write(() => {
    vault.stateKey.set(o.stateKey ?? PrivateKey.random().toPublicKey());
    vault.treasury.set(treasury);
    o.write?.(vault);
    if (o.timed) {
      vault.self.account.timing.set({
        initialMinimumBalance: UInt64.from(1), cliffTime: Mina.getNetworkState().globalSlotSinceGenesis.add(1000),
        cliffAmount: UInt64.from(0), vestingPeriod: UInt32.from(1),
        vestingIncrement: UInt64.from(0),
      });
    }
  });
  await write(() => vault.self.account.permissions.set({ ...LOCKED(), ...o.permissions }));
  return vault;
}

export const phantomDeposit = (secret = 7n) => VaultAction.deposit(commitSecret(Field(secret)), UInt64.from(SMALL), UInt64.from(now()));
export const forgedClose = (destination: PublicKey) => VaultAction.mutualClose(new WithdrawalPublic({
  ...WithdrawalPublic.empty(), kind: Field(WithdrawalKind.mutualClose), nullifier: Field(5), amount: Field(SMALL), size: Field(SMALL),
  requestTime: Field(now()), destination,
}));
/** Dispatches `deposit` and writes the note state a reduce of it would leave. */
export function writeReducedDeposit(vault: Vault, deposit: VaultAction) {
  const tree = new NoteTree();
  tree.append({ commitment: deposit.commitment, size: deposit.size.value, depositTime: deposit.time.value });
  dispatch(vault, deposit);
  vault.noteRoot.set(tree.root);
  vault.nextLeafIndex.set(Field(1));
  vault.rootRing.set(RootRing.empty().push(tree.root));
}

/**
 * `inner`, but with `vaults` also listed by `registry`, as a registry that listed them would show: for judging a forged
 * vault by every rule other than the registry's. The registry is read from `chain`; its action state is extended to match.
 */
export function listing(inner: VaultReader, chain: VaultReader, registry: PublicKey, ...vaults: PublicKey[]): VaultReader {
  const extra = vaults.map((v) => [PublicKey.toFields(v).map((f) => f.toString())]);
  return {
    ...inner,
    async actions(address) {
      return address.equals(registry).toBoolean() ? [...(await chain.actions(address)), ...extra] : inner.actions(address);
    },
    async account(address) {
      const account = await inner.account(address);
      if (!account?.zkapp || !address.equals(registry).toBoolean()) return account;
      const [state, ...rest] = account.zkapp.actionState;
      const extended = extra.reduce((acc, l) => AccountUpdate.Actions.updateSequenceState(acc, AccountUpdate.Actions.fromJSON(l).hash), state!);
      return { ...account, zkapp: { ...account.zkapp, actionState: [extended, ...rest] } };
    },
  };
}
