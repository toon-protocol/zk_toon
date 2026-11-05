// The registry's sighting (ADR 0011, #81) with proofs off: what makes a deployment record reproducible from the published
// deploy command, an archive and a node, and what each way of faking one looks like.
import { beforeAll, describe, expect, it } from 'vitest';
import { AccountUpdate, Experimental, Mina, PrivateKey, PublicKey } from 'o1js';
import { type SightingEvidence, sightingProblems } from './registry-sighting.js';
import { permissionsWanted } from './vault-check.js';
import { registryDeployTx } from './vault-registry.js';

const Local = await Mina.LocalBlockchain({ proofsEnabled: false });
Mina.setActiveInstance(Local);
const [payer] = Local.testAccounts;
const empty = Experimental.BatchReducer.initialActionState.toString();

type Command = { accountUpdates: { body: { publicKey: string; update: { verificationKey: { data: string; hash: string } | null } } }[] };
let honest: SightingEvidence;
let codeHash: string;
let keyData: string;

/** The evidence for a registry deployed by `tx`, seen at the deploy's slot, as the archive and node would answer. */
async function evidence(tx: Awaited<ReturnType<typeof Mina.transaction>>, registry: PublicKey): Promise<SightingEvidence> {
  const command = JSON.parse(tx.toJSON());
  const hash = await Mina.Transaction.hash(command);
  return {
    record: { network: 'devnet', registry: registry.toBase58(), slot: '100', actionState: empty, transaction: hash },
    command,
    commandHash: hash,
    height: '50',
    block: { failure: null },
    actionHeights: [],
    actions: [],
    account: { verificationKeyHash: codeHash, permissions: permissionsWanted(), actionState: empty },
  };
}

beforeAll(async () => {
  const key = PrivateKey.random();
  const { tx } = await registryDeployTx(payer, key);
  const command = JSON.parse(tx.toJSON()) as Command;
  ({ hash: codeHash, data: keyData } = command.accountUpdates.find((u) => u.body.publicKey === key.toPublicKey().toBase58())!.body.update.verificationKey!);
  honest = await evidence(tx, key.toPublicKey());
});

const problems = (e: SightingEvidence) => sightingProblems(e, { registryCodeHash: codeHash, registryKeyData: keyData });

describe("the registry's sighting", () => {
  it('holds for a registry its command created locked, with nothing dispatched by the recorded slot', () => {
    expect(problems(honest)).toEqual([]);
  });

  it('refuses a command that is not the recorded transaction', () => {
    expect(problems({ ...honest, commandHash: '5Jsomethingelse' })).toEqual([
      `the published command hashes to 5Jsomethingelse, not the recorded transaction ${honest.record.transaction}`,
    ]);
  });

  it("refuses when the archive doesn't list the command as applied at the published height", () => {
    expect(problems({ ...honest, block: undefined })).toEqual([`the archive lists no block with ${honest.record.transaction}`]);
    expect(problems({ ...honest, block: { failure: 'Cancelled' } })).toEqual(['the deploy failed on chain: Cancelled']);
  });

  it("refuses a deploy that doesn't require a new account, or doesn't lock it, or carries another key", async () => {
    const key = PrivateKey.random();
    const { tx, registry } = await registryDeployTx(payer, key);
    const update = tx.transaction.accountUpdates.find((u) => u.body.publicKey.equals(key.toPublicKey()).toBoolean())!;
    update.body.preconditions.account.isNew.isSome = update.body.preconditions.account.isNew.isSome.not();
    update.body.update.permissions.isSome = update.body.update.permissions.isSome.not();
    const e = await evidence(tx, registry.address);
    expect(problems(e)).toEqual([
      "the command's update of the registry doesn't require a new account",
      "the command doesn't set the registry's permissions to ADR 0006's table",
    ]);
    expect(sightingProblems(honest, { registryCodeHash: '1', registryKeyData: keyData })).toEqual([
      `the command gives the registry key hash ${codeHash}, not the published 1`,
      `the registry's key hash on chain is ${codeHash}, not the published 1`,
    ]);
  });

  it("refuses the published key hash with another key's data, as a node accepts", () => {
    expect(sightingProblems(honest, { registryCodeHash: codeHash, registryKeyData: 'other' })).toEqual([
      "the command gives the registry the published key hash with another key's data",
    ]);
  });

  it('refuses a command that dispatches, or an action by the recorded slot', async () => {
    const key = PrivateKey.random();
    const { tx, registry } = await registryDeployTx(payer, key);
    const update = tx.transaction.accountUpdates.find((u) => u.body.publicKey.equals(key.toPublicKey()).toBoolean())!;
    update.body.actions = AccountUpdate.Actions.pushEvent(update.body.actions, PublicKey.toFields(key.toPublicKey()));
    expect(problems(await evidence(tx, registry.address))).toEqual(["the command dispatches actions to the registry"]);
    const entry = [PublicKey.toFields(key.toPublicKey()).map(String)];
    const state = AccountUpdate.Actions.updateSequenceState(Experimental.BatchReducer.initialActionState, AccountUpdate.Actions.fromJSON(entry).hash).toString();
    const account = { ...honest.account!, actionState: state };
    expect(problems({ ...honest, account, actions: [entry], actionHeights: ['50'] })).toEqual(["the registry has an action at height 50, by the deploy's height 50"]);
    expect(problems({ ...honest, account, actions: [entry], actionHeights: ['51'] })).toEqual([]);
  });

  it("refuses an archive whose actions don't hash to the registry's action state, or a registry not locked now", () => {
    expect(problems({ ...honest, account: { ...honest.account!, actionState: '5' } })).toEqual([
      "the archive's registry actions don't hash to its action state on chain",
    ]);
    expect(problems({ ...honest, account: undefined })).toEqual([`the node has no account at ${honest.record.registry}`]);
    const permissions = { ...permissionsWanted(), setPermissions: 'Signature' };
    expect(problems({ ...honest, account: { ...honest.account!, permissions } })).toEqual([
      "the registry's permission setPermissions on chain is \"Signature\", expected \"Impossible\"",
    ]);
  });
});
