// What a zkApp's payout does to an account that doesn't exist yet. The vault refuses such a destination today
// (`requireAccountExists`, ADR 0002); this pins the chain behaviour a payout that opens the account would rely on.
// o1js leaves `implicitAccountCreationFee` off on a send's receiver, so a plain send to a new account is refused
// unless the transaction pays the fee elsewhere. With the flag on, the fee comes out of the payout: only when the
// account is new, and a payout below the fee is refused. A payout can also require its receiver to be new, or not.
// Proofs are off: the ledger rules (balances, the creation fee, preconditions) are the chain's, authorization is
// not checked.
import { describe, expect, it } from 'vitest';
import { AccountUpdate, Bool, Mina, PrivateKey, PublicKey, SmartContract, UInt64, declareMethods } from 'o1js';

const MINA = 1_000_000_000n;
const CREATION_FEE = MINA;

class Payer extends SmartContract {
  /** Sends `amount` to `to`, as the vault's reduce does today (`payIf`). */
  async payPlain(to: PublicKey, amount: UInt64) {
    this.send({ to, amount });
  }
  /** The same, with the creation fee taken from the payout when `to` is new. */
  async pay(to: PublicKey, amount: UInt64) {
    this.send({ to, amount }).body.implicitAccountCreationFee = Bool(true);
  }
  /** As `pay`, with a precondition that `to` is new exactly when `isNew` says so. */
  async payExpecting(to: PublicKey, amount: UInt64, isNew: Bool) {
    const receiver = this.send({ to, amount });
    receiver.body.implicitAccountCreationFee = Bool(true);
    receiver.account.isNew.requireEquals(isNew);
  }
  /** An update on `to` that moves nothing, with a precondition that it is new. */
  async touchNew(to: PublicKey) {
    AccountUpdate.create(to).account.isNew.requireEquals(Bool(true));
  }
}
declareMethods(Payer, {
  payPlain: [PublicKey, UInt64],
  pay: [PublicKey, UInt64],
  payExpecting: [PublicKey, UInt64, Bool],
  touchNew: [PublicKey],
} as Record<string, any[]>);

const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
const [sender] = Local.testAccounts;

const payerKey = PrivateKey.random();
const payer = new Payer(payerKey.toPublicKey());
{
  const tx = await Mina.transaction(sender, async () => {
    AccountUpdate.fundNewAccount(sender);
    await payer.deploy();
    AccountUpdate.createSigned(sender).send({ to: payer.address, amount: 100n * MINA });
  });
  await tx.prove();
  await (await tx.sign([sender.key, payerKey]).send()).wait();
}

const balance = (address: PublicKey) => Mina.getAccount(address).balance.toBigInt();
const exists = (address: PublicKey) => Mina.hasAccount(address);
const fresh = () => PrivateKey.random().toPublicKey();

/** Sends a transaction with `body` run inside it; the error message if the chain refuses it, else undefined. */
async function run(body: () => Promise<void>): Promise<string | undefined> {
  try {
    const tx = await Mina.transaction(sender, body);
    await tx.prove();
    await (await tx.sign([sender.key]).send()).wait();
    return undefined;
  } catch (e) {
    return String((e as Error).message);
  }
}

describe('a zkApp payout to an account that does not exist', { timeout: 120_000 }, () => {
  it("leaves the implicit creation fee flag off on a send's receiver", async () => {
    let flag: boolean | undefined;
    await Mina.transaction(sender, async () => {
      const receiver = AccountUpdate.create(payer.address).send({ to: fresh(), amount: UInt64.from(10n * MINA) });
      flag = receiver.body.implicitAccountCreationFee.toBoolean();
    });
    expect(flag).toBe(false);
  });

  it('refuses a plain send to a new account: nothing in the transaction pays the fee', async () => {
    const to = fresh();
    const refused = await run(() => payer.payPlain(to, UInt64.from(10n * MINA)));
    expect(refused).toContain('Invalid_fee_excess');
    expect(exists(to)).toBe(false);
  });

  it('opens the account and takes the creation fee out of the payout', async () => {
    const to = fresh();
    const before = balance(payer.address);
    expect(await run(() => payer.pay(to, UInt64.from(10n * MINA)))).toBeUndefined();
    expect(exists(to)).toBe(true);
    expect(balance(to)).toBe(10n * MINA - CREATION_FEE);
    expect(before - balance(payer.address)).toBe(10n * MINA);
  });

  it('takes no fee when the account exists', async () => {
    const to = fresh();
    await run(() => payer.pay(to, UInt64.from(10n * MINA)));
    const before = balance(to);
    expect(await run(() => payer.pay(to, UInt64.from(10n * MINA)))).toBeUndefined();
    expect(balance(to) - before).toBe(10n * MINA);
  });

  it('opens it with a payout of exactly the fee, at a balance of zero', async () => {
    const to = fresh();
    expect(await run(() => payer.pay(to, UInt64.from(CREATION_FEE)))).toBeUndefined();
    expect(exists(to)).toBe(true);
    expect(balance(to)).toBe(0n);
  });

  it('refuses the whole transaction when the payout is below the fee', async () => {
    const to = fresh();
    const before = balance(payer.address);
    const refused = await run(() => payer.pay(to, UInt64.from(CREATION_FEE / 2n)));
    expect(refused).toBeDefined();
    expect(exists(to)).toBe(false);
    expect(balance(payer.address)).toBe(before);
  });

  it('can require the receiver to be new, or not, on the payout itself', async () => {
    const to = fresh();
    expect(await run(() => payer.payExpecting(to, UInt64.from(10n * MINA), Bool(false)))).toBeDefined();
    expect(exists(to)).toBe(false);
    expect(await run(() => payer.payExpecting(to, UInt64.from(10n * MINA), Bool(true)))).toBeUndefined();
    expect(await run(() => payer.payExpecting(to, UInt64.from(10n * MINA), Bool(true)))).toBeDefined();
    expect(await run(() => payer.payExpecting(to, UInt64.from(10n * MINA), Bool(false)))).toBeUndefined();
  });

  it('refuses an update that moves nothing on an account that does not exist', async () => {
    const to = fresh();
    const refused = await run(() => payer.touchNew(to));
    expect(refused).toBeDefined();
    expect(exists(to)).toBe(false);
  });
});
