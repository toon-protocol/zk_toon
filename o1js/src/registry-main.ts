// `npm run registry -- deploy | sighting | check <vault>`: the vault registry on Mina devnet (ADR 0011, #81).
//
// `deploy` deploys a registry from the dev funder, locked in the command that creates it, under a random key that is
// never written down: the registry is replaced at a fork, not upgraded, so nobody need hold its key. It publishes the
// command beside the devnet write-up, checks the sighting and only then writes the record to `registry-deployments.json`.
// Run again after a stop, it waits for the command it published instead of deploying a second registry.
// `sighting` reproduces the record from the archive, the node and the published command. `check` runs the vault check
// on an address against the recorded registry. Set `MINA_GRAPHQL` and `MINA_ARCHIVE` to use other endpoints.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { Experimental, Mina, PrivateKey, PublicKey, UInt64 } from 'o1js';
import { minaKeyFromMnemonic } from './devnet.js';
import { buildKeys } from './keys.js';
import { REGISTRY_DEPLOYMENTS_PATH, type RegistryDeployment, readDeployments } from './registry-deployments.js';
import { deployCommandPath, readSighting, sightingProblems } from './registry-sighting.js';
import { chainReader, checkVault } from './vault-check.js';
import { registryDeployTx } from './vault-registry.js';

const MINA_URL = process.env.MINA_GRAPHQL ?? 'https://devnet-plain-1.gcp.o1test.net/graphql';
const ARCHIVE_URL = process.env.MINA_ARCHIVE ?? 'https://devnet-archive-node-api.gcp.o1test.net';
const FUNDER_ADDRESS = 'B62qp9YT9mw27enrwPR3gSPeRkXxAg1runhKK7mx6jj64Lq6EukJRTy';
const FEE = 100_000_000n;
const NETWORK = 'devnet';
const INCLUSION_TIMEOUT_MS = 40 * 60_000;

const [command, ...rest] = process.argv.slice(2);
const wellFormed = (command === 'deploy' || command === 'sighting') ? rest.length === 0 : command === 'check' && rest.length === 1;
if (!wellFormed) {
  console.error('usage: npm run registry -- deploy | sighting | check <vault address>');
  process.exit(2);
}

const log = (message: string) => console.log(`${new Date().toISOString()} ${message}`);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
Mina.setActiveInstance(Mina.Network({ mina: MINA_URL, archive: ARCHIVE_URL }));

/** The checked-in deploy command, once `deploy` has sent it. */
type Published = { network: string; registry: string; transaction: string; height?: string; slot?: string; command: unknown };
const publishedPath = deployCommandPath(NETWORK);
const readPublished = (): Published | undefined => (existsSync(publishedPath) ? JSON.parse(readFileSync(publishedPath, 'utf8')) : undefined);
const writePublished = (p: Published) => writeFileSync(publishedPath, `${JSON.stringify(p, null, 2)}\n`);

async function graphql<T>(query: string): Promise<T> {
  const response = await fetch(MINA_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query }) });
  const body = (await response.json()) as { data?: T; errors?: unknown };
  if (!body.data) throw Error(`GraphQL: ${JSON.stringify(body.errors)}`);
  return body.data;
}
type Block = { protocolState: { consensusState: { slotSinceGenesis: string; blockHeight: string } }; transactions: { zkappCommands: { hash: string; failureReason: unknown }[] } };

/** Waits for `hash` in the node's best chain; a command that fails is included too. */
async function inclusion(hash: string) {
  const deadline = Date.now() + INCLUSION_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const { bestChain } = await graphql<{ bestChain: Block[] }>(`{ bestChain(maxLength: 290) {
      protocolState { consensusState { slotSinceGenesis blockHeight } } transactions { zkappCommands { hash failureReason { index failures } } } } }`);
    for (const block of bestChain) {
      const found = block.transactions.zkappCommands.find((c) => c.hash === hash);
      if (found) return { ...block.protocolState.consensusState, failure: found.failureReason };
    }
    await sleep(15_000);
  }
  throw Error(`${hash} was not included within ${INCLUSION_TIMEOUT_MS / 60_000} minutes`);
}

/** Reproduces `record`'s sighting, waiting a while for the archive to catch up. Answers what is wrong, if anything. */
async function sighting(record: RegistryDeployment, { wait = false } = {}) {
  for (let tries = 0; ; tries++) {
    const problems = sightingProblems(await readSighting(record, ARCHIVE_URL), { registryCodeHash: keys.registry.codeHash, registryKeyData: keys.registry.verificationKey.data });
    if (problems.length === 0 || !wait || tries >= 40) return problems;
    log(`sighting: ${problems.join('; ')}; the archive may be behind, trying again`);
    await sleep(30_000);
  }
}

const keys = await buildKeys();
const recorded = () => readDeployments().find((d) => d.network === NETWORK);

if (command === 'deploy') {
  if (recorded()) throw Error(`registry-deployments.json already records a ${NETWORK} registry`);
  let published = readPublished();
  if (!published) {
    const mnemonic = process.env.TOON_FUNDER_MNEMONIC;
    if (!mnemonic) throw Error('TOON_FUNDER_MNEMONIC is not set');
    const funderKey = minaKeyFromMnemonic(mnemonic);
    if (funderKey.toPublicKey().toBase58() !== FUNDER_ADDRESS) throw Error('the mnemonic does not derive the dev funder');
    // Discarded: it lives only in this process (ADR 0011).
    const registryKey = PrivateKey.random();
    const { tx } = await registryDeployTx({ sender: funderKey.toPublicKey(), fee: UInt64.from(FEE) }, registryKey);
    await tx.prove();
    tx.sign([funderKey, registryKey]);
    const sent = await tx.send();
    if (sent.status === 'rejected') throw Error(`refused: ${JSON.stringify(sent.errors)}`);
    published = { network: NETWORK, registry: registryKey.toPublicKey().toBase58(), transaction: sent.hash, command: JSON.parse(tx.toJSON()) };
    writePublished(published);
    log(`sent ${sent.hash}: the registry at ${published.registry}`);
  }
  if (published.height === undefined) {
    const landed = await inclusion(published.transaction);
    if (landed.failure) throw Error(`the deploy failed on chain: ${JSON.stringify(landed.failure)}`);
    published = { ...published, height: landed.blockHeight, slot: landed.slotSinceGenesis };
    writePublished(published);
    log(`applied in slot ${landed.slotSinceGenesis}, block ${landed.blockHeight}`);
  }
  const record: RegistryDeployment = {
    network: NETWORK, registry: published.registry, slot: published.slot!,
    actionState: Experimental.BatchReducer.initialActionState.toString(), transaction: published.transaction,
  };
  const problems = await sighting(record, { wait: true });
  if (problems.length > 0) throw Error(`the sighting does not hold, so nothing is recorded: ${problems.join('; ')}`);
  const file = JSON.parse(readFileSync(REGISTRY_DEPLOYMENTS_PATH, 'utf8')) as { deployments: RegistryDeployment[] };
  file.deployments.push(record);
  readDeployments(file);
  writeFileSync(REGISTRY_DEPLOYMENTS_PATH, `${JSON.stringify(file, null, 2)}\n`);
  log(`recorded: ${JSON.stringify(record)}`);
} else {
  const record = recorded();
  if (!record) throw Error(`registry-deployments.json records no ${NETWORK} registry`);
  if (command === 'sighting') {
    const problems = await sighting(record);
    log(problems.length === 0 ? `the sighting holds: ${record.registry} was empty and locked at slot ${record.slot}` : `the sighting does not hold: ${problems.join('; ')}`);
    process.exit(problems.length === 0 ? 0 : 1);
  }
  const verdict = await checkVault(PublicKey.fromBase58(rest[0]!), {
    codeHash: keys.vault.codeHash, registryCodeHash: keys.registry.codeHash,
    registry: PublicKey.fromBase58(record.registry), reader: chainReader({ localChain: false }),
  });
  console.log(JSON.stringify(verdict, null, 2));
  process.exit(verdict.pass ? 0 : 1);
}
process.exit(0);
