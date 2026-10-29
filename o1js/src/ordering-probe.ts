// A throwaway zkApp for #33: does an account update's precondition see the ledger as earlier account
// updates in the same zkApp command left it? `write` sets a state field and dispatches an action; `read`
// has equality preconditions on that field and on the action state. One command calls both, in order.
import {
  AccountUpdate, Field, Mina, PrivateKey, Reducer, SmartContract, State, declareMethods, declareState,
} from 'o1js';

export class OrderingProbe extends SmartContract {
  x = State<Field>();
  reducer = Reducer({ actionType: Field });

  async write(value: Field) {
    this.x.set(value);
    this.reducer.dispatch(value);
  }

  async read(x: Field, actionState: Field) {
    this.x.requireEquals(x);
    this.account.actionState.requireEquals(actionState);
  }
}

// declareMethods' argument type is looser than the types it accepts.
declareMethods(OrderingProbe, { write: [Field], read: [Field, Field] } as Record<string, any[]>);
declareState(OrderingProbe, { x: Field });

/** Fee per command. LocalBlockchain ignores it; a lightnet needs one. */
const FEE = 100_000_000;

export type Outcome = { status: 'included' | 'rejected'; errors: string[] };

/** Sends a signed, proved command and waits for its block. */
async function submit(tx: Mina.Transaction<false, false>, keys: PrivateKey[]): Promise<Outcome> {
  await tx.prove();
  const sent = await tx.sign(keys).safeSend();
  if (sent.status === 'rejected') return { status: 'rejected', errors: sent.errors.map(String) };
  const done = await sent.safeWait();
  if (done.status === 'rejected') return { status: 'rejected', errors: done.errors.map(String) };
  return { status: 'included', errors: [] };
}

export async function deployProbe(probe: OrderingProbe, probeKey: PrivateKey, sender: Mina.TestPublicKey) {
  if (Mina.getProofsEnabled()) await OrderingProbe.compile();
  const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
    AccountUpdate.fundNewAccount(sender);
    await probe.deploy();
  });
  const outcome = await submit(tx, [sender.key, probeKey]);
  if (outcome.status !== 'included') throw Error(`deploy failed: ${outcome.errors.join('; ')}`);
}

/**
 * The probe's state field, latest action state and last five action states, newest first, as o1js last
 * saw them: on a network, call `fetchAccount` first.
 */
export function cachedState(probe: OrderingProbe) {
  const { zkapp } = Mina.getAccount(probe.address);
  const actionStates = zkapp!.actionState.map((s) => s.toBigInt());
  return { x: zkapp!.appState[0].toBigInt(), actionState: actionStates[0], actionStates };
}

/**
 * One command with two account updates on the probe: `write(value)`, then `read` with preconditions on
 * the value `write` leaves (`new`), the value before the command (`old`), or a given value.
 */
export async function writeThenRead(
  probe: OrderingProbe,
  sender: Mina.TestPublicKey,
  value: Field,
  preconditions: { x: 'old' | 'new'; actionState: 'old' | 'new' | Field }
): Promise<Outcome> {
  const before = cachedState(probe);
  const after = { x: value.toBigInt(), actionState: actionStateAfter(Field(before.actionState), value).toBigInt() };
  const x = Field(preconditions.x === 'new' ? after.x : before.x);
  const actionState =
    preconditions.actionState === 'new' ? Field(after.actionState)
    : preconditions.actionState === 'old' ? Field(before.actionState)
    : preconditions.actionState;
  const tx = await Mina.transaction({ sender, fee: FEE }, async () => {
    await probe.write(value);
    await probe.read(x, actionState);
  });
  return submit(tx, [sender.key]);
}

/** The action state after one `write(value)` on top of `state`. */
function actionStateAfter(state: Field, value: Field): Field {
  const { Actions } = AccountUpdate;
  return Actions.updateSequenceState(state, Actions.pushEvent(Actions.empty(), [value]).hash);
}
