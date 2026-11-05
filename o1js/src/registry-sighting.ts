// The registry's sighting (ADR 0011): a deployment record says a registry was empty and locked at a slot, and anyone can
// reproduce that. The public archive API serves action lists and command hashes, not commands, so the deploy command is
// published beside the record. Its hash is the recorded transaction, an archive lists it as applied by the recorded slot,
// and it shows on its face that the update creating the account (`isNew`) locked it and dispatched nothing. From then on
// an action needs the registry's proof, so the record holds if the archive lists no action by that slot and its actions
// hash to the registry's action state on chain. See docs/devnet-smoke.md for the steps.
import { readFileSync } from 'node:fs';
import { Experimental, Mina, PublicKey, Types, fetchAccount } from 'o1js';
import type { RegistryDeployment } from './registry-deployments.js';
import { extendActionState, permissionsWanted } from './vault-check.js';

/** What the sighting depends on, as JSON. */
export type SightingEvidence = {
  record: RegistryDeployment;
  /** The published deploy command. */
  command: unknown;
  /** What `Mina.Transaction.hash` gives for `command`. */
  commandHash: string;
  /** The archive's block that lists the recorded transaction, if any, with the command's failure. */
  block?: { slot: string; failure: string | null };
  /** The registry's actions as the archive has them, one list per account update, oldest first. */
  actions: string[][][];
  /** The slot of the block of each list in `actions`. */
  actionSlots: string[];
  /** The registry as the node has it now. */
  account?: { verificationKeyHash: string | null; permissions: Record<string, unknown>; actionState: string };
};

type CommandUpdate = {
  body: {
    publicKey: string;
    update: { verificationKey: { hash: string } | null; permissions: Record<string, unknown> | null };
    preconditions: { account: { isNew: boolean | null } };
    actions: string[][];
  };
};

/** What is wrong with the sighting; empty when the record holds. */
export function sightingProblems(e: SightingEvidence, { registryCodeHash }: { registryCodeHash: string }): string[] {
  const problems: string[] = [];
  const { record } = e;
  if (e.commandHash !== record.transaction) {
    problems.push(`the published command hashes to ${e.commandHash}, not the recorded transaction ${record.transaction}`);
  }
  if (!e.block) problems.push(`the archive lists no block with ${record.transaction}`);
  else if (e.block.failure) problems.push(`the deploy failed on chain: ${e.block.failure}`);
  else if (BigInt(e.block.slot) > BigInt(record.slot)) problems.push(`the deploy landed in slot ${e.block.slot}, after the recorded slot ${record.slot}`);

  const updates = (e.command as { accountUpdates?: CommandUpdate[] }).accountUpdates ?? [];
  const own = updates.filter((u) => u.body.publicKey === record.registry);
  const creating = own.find((u) => u.body.preconditions.account.isNew === true);
  if (!creating) problems.push("the command's update of the registry doesn't require a new account");
  const update = creating ?? own[0];
  if (!update) return [...problems, 'the command has no update of the registry'];
  const key = update.body.update.verificationKey?.hash ?? 'none';
  if (key !== registryCodeHash) problems.push(`the command gives the registry key hash ${key}, not the published ${registryCodeHash}`);
  const set = update.body.update.permissions;
  if (!set || Object.entries(permissionsWanted()).some(([name, want]) => JSON.stringify(set[name]) !== JSON.stringify(want))) {
    problems.push("the command doesn't set the registry's permissions to ADR 0006's table");
  }
  if (own.some((u) => u.body.actions.length > 0)) problems.push('the command dispatches actions to the registry');

  const early = e.actionSlots.find((s) => BigInt(s) <= BigInt(record.slot));
  if (early !== undefined) problems.push(`the registry has an action in slot ${early}, by the recorded slot ${record.slot}`);

  if (!e.account) return [...problems, `the node has no account at ${record.registry}`];
  const state = extendActionState(Experimental.BatchReducer.initialActionState, e.actions).toString();
  if (state !== e.account.actionState) problems.push("the archive's registry actions don't hash to its action state on chain");
  const onChain = e.account.verificationKeyHash ?? 'none';
  if (onChain !== registryCodeHash) problems.push(`the registry's key hash on chain is ${onChain}, not the published ${registryCodeHash}`);
  for (const [name, want] of Object.entries(permissionsWanted())) {
    const got = JSON.stringify(e.account.permissions[name]);
    if (got !== JSON.stringify(want)) problems.push(`the registry's permission ${name} on chain is ${got}, expected ${JSON.stringify(want)}`);
  }
  return problems;
}

/** Where a network's published deploy command is kept, beside the devnet write-up. */
export const deployCommandPath = (network: string) => new URL(`../../docs/devnet-smoke/registry-${network}.json`, import.meta.url);

async function query<T>(url: string, query: string, variables: object = {}): Promise<T> {
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query, variables }) });
  const body = (await response.json()) as { data?: T; errors?: unknown };
  if (!body.data) throw Error(`${url}: ${JSON.stringify(body.errors)}`);
  return body.data;
}

/** The archive's block at `height`, if it lists `hash`, with the command's failure. */
export async function archivedCommand(archive: string, height: string, hash: string) {
  const { blocks } = await query<{ blocks: { blockHeight: number; protocolState: { consensusState: { slotSinceGenesis: string } }; transactions: { zkappCommands: { hash: string; failureReason: string | null }[] } }[] }>(
    archive,
    `query($h: Int!) { blocks(limit: 1, query: { blockHeight_gte: $h }) {
      blockHeight protocolState { consensusState { slotSinceGenesis } } transactions { zkappCommands { hash failureReason } } } }`,
    { h: Number(height) },
  );
  const block = blocks.find((b) => String(b.blockHeight) === height);
  const found = block?.transactions.zkappCommands.find((c) => c.hash === hash);
  return block && found ? { slot: block.protocolState.consensusState.slotSinceGenesis, failure: found.failureReason } : undefined;
}

/** Reads the evidence for `record` from the archive and node of the active Mina instance. */
export async function readSighting(record: RegistryDeployment, archive: string): Promise<SightingEvidence> {
  const published = JSON.parse(readFileSync(deployCommandPath(record.network), 'utf8')) as { height: string; command: unknown };
  const address = PublicKey.fromBase58(record.registry);
  const lists = await Mina.fetchActions(address);
  if ('error' in lists) throw Error(JSON.stringify(lists.error));
  const { actions } = await query<{ actions: { blockInfo: { globalSlotSinceGenesis: number } }[] }>(
    archive, 'query($a: String!) { actions(input: { address: $a }) { blockInfo { globalSlotSinceGenesis } } }', { a: record.registry },
  );
  const { account } = await fetchAccount({ publicKey: address });
  const json = account ? Types.Account.toJSON(account) : undefined;
  return {
    record,
    command: published.command,
    commandHash: await Mina.Transaction.hash(published.command as never),
    block: await archivedCommand(archive, published.height, record.transaction),
    actions: lists.map((l) => l.actions),
    actionSlots: actions.map((a) => String(a.blockInfo.globalSlotSinceGenesis)),
    account: account && json ? {
      verificationKeyHash: account.zkapp?.verificationKey?.hash.toString() ?? null,
      permissions: json.permissions as Record<string, unknown>,
      actionState: account.zkapp?.actionState[0]?.toString() ?? '',
    } : undefined,
  };
}
