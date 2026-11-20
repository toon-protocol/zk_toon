// The published verification keys (#16): each build compiles the circuits and the vault of every live generation
// (ADR 0015) and writes their keys, so a zk edge's greeting pins (toon-protocol/connector#1511) can be checked against what
// was deployed. The vault's code hash is the hash of its verification key: the key a deployed vault
// account carries, and the only code a zkApp account has.
import { readFileSync } from 'node:fs';
import { Cache, type Field } from 'o1js';
import { CURRENT_GENERATION_ID, GENERATIONS, type Generation, generationById } from './policy.js';
import { vaultBuild } from './vault.js';
import { registryClass } from './vault-registry.js';

/** A verification key as o1js serialises it: base64 `data`, and its `hash`, a field in decimal. */
export type PublishedKey = { data: string; hash: string };
export type PublishedCircuit = { name: string; methods?: string[]; verificationKey: PublishedKey };

/** What one vault generation (ADR 0015) publishes: its circuits and its vault, built with its constants. */
export type GenerationKeys = {
  circuits: {
    /** The request proof (`zk-toon-request`): a zk edge checks it, and the vault takes it as evidence. */
    request: PublishedCircuit;
    /** The withdrawal proof: mutual close, escape and ownership. */
    withdrawal: PublishedCircuit;
    /** The vault's batch reducer, whose proof the vault's `reduce` checks. */
    vaultReducer: PublishedCircuit;
  };
  vault: { codeHash: string; methods: string[]; verificationKey: PublishedKey };
};

export type Keys = {
  /** The exact o1js version the keys were compiled with; another version may compile other keys. */
  o1js: string;
  /** The id of the current generation: the one new vaults are deployed with and the registry fixes. */
  current: string;
  /** The keys of every live generation, by id. */
  generations: Record<string, GenerationKeys>;
  /** The vault registry (ADR 0011), built for the current generation's vault code hash. Its address is no build output: see `registry-deployments.json`. */
  registry: { codeHash: string; methods: string[]; verificationKey: PublishedKey };
};

/** A compiled key in its published form. */
export const published = (vk: { data: string; hash: { toString(): string } }): PublishedKey =>
  ({ data: vk.data, hash: vk.hash.toString() });

/** The keys of the current generation: what `Keys` names by `current`. */
export const currentKeys = (keys: Keys): GenerationKeys => {
  const g = keys.generations[keys.current];
  if (!g) throw Error(`the published keys name no generation '${keys.current}'`);
  return g;
};

/** Compiles one generation's circuits, then its vault, which checks their proofs, and returns their keys. */
async function buildGenerationKeys(gen: Generation, cache: Cache) {
  const { Vault, batchReducer, RequestProgram, WithdrawalProgram } = vaultBuild(gen);
  const request = await RequestProgram.compile({ cache });
  const withdrawal = await WithdrawalProgram.compile({ cache });
  // `batchReducer.compile()` takes no options; its program's `compile` does, though its type says not.
  const reducer = await (batchReducer.program.compile as (o: { cache: Cache }) => ReturnType<typeof batchReducer.compile>)({ cache });
  const vault = await Vault.compile({ cache });
  const keys: GenerationKeys = {
    circuits: {
      request: { name: RequestProgram.name, methods: Object.keys(RequestProgram.rawMethods), verificationKey: published(request.verificationKey) },
      withdrawal: { name: WithdrawalProgram.name, methods: Object.keys(WithdrawalProgram.rawMethods), verificationKey: published(withdrawal.verificationKey) },
      vaultReducer: { name: batchReducer.program.name, verificationKey: published(reducer.verificationKey) },
    },
    vault: {
      codeHash: vault.verificationKey.hash.toString(),
      methods: (Vault._methods ?? []).map((m) => m.methodName),
      verificationKey: published(vault.verificationKey),
    },
  };
  return { keys, vaultHash: vault.verificationKey.hash };
}

/**
 * Compiles every generation of `generations` (the policy's table, unless a test gives another), then the registry for
 * the current one, and returns their keys. Throws if a vault doesn't compile, for example when a method outgrows one
 * circuit. `cache` is o1js's key cache; `Cache.None` compiles everything afresh.
 */
export async function buildKeys(
  { cache = Cache.FileSystemDefault, generations = GENERATIONS, current = CURRENT_GENERATION_ID }:
    { cache?: Cache; generations?: readonly Generation[]; current?: string } = {},
): Promise<Keys> {
  const o1js = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.o1js;
  generationById(current, generations);
  const built: Record<string, GenerationKeys> = {};
  let currentHash: Field | undefined;
  for (const gen of generations) {
    const { keys, vaultHash } = await buildGenerationKeys(gen, cache);
    built[gen.id] = keys;
    if (gen.id === current) currentHash = vaultHash;
  }
  // The registry fixes the current vault's code hash in its circuit, so it compiles after the vault.
  const Registry = await registryClass(currentHash!, { cache, compile: true });
  const registryKey = Registry._verificationKey!;
  return {
    o1js,
    current,
    generations: built,
    registry: {
      codeHash: registryKey.hash.toString(),
      methods: (Registry._methods ?? []).map((m) => m.methodName),
      verificationKey: published(registryKey),
    },
  };
}
