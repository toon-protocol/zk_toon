// The published verification keys (#16): each build compiles the circuits and the vault and writes
// their keys, so a zk edge's greeting pins (toon-protocol/connector#1511) can be checked against what
// was deployed. The vault's code hash is the hash of its verification key: the key a deployed vault
// account carries, and the only code a zkApp account has.
import { readFileSync } from 'node:fs';
import { Cache } from 'o1js';
import { RequestProgram } from './request.js';
import { Vault, batchReducer } from './vault.js';
import { WithdrawalProgram } from './withdrawal.js';

/** A verification key as o1js serialises it: base64 `data`, and its `hash`, a field in decimal. */
export type PublishedKey = { data: string; hash: string };
export type PublishedCircuit = { name: string; methods?: string[]; verificationKey: PublishedKey };

export type Keys = {
  /** The exact o1js version the keys were compiled with; another version may compile other keys. */
  o1js: string;
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

const published = (vk: { data: string; hash: { toString(): string } }): PublishedKey =>
  ({ data: vk.data, hash: vk.hash.toString() });

/**
 * Compiles every circuit, then the vault, which checks their proofs, and returns their keys. Throws
 * if the vault doesn't compile, for example when a method outgrows one circuit. `cache` is o1js's key
 * cache; `Cache.None` compiles everything afresh.
 */
export async function buildKeys({ cache = Cache.FileSystemDefault }: { cache?: Cache } = {}): Promise<Keys> {
  const o1js = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).dependencies.o1js;
  const request = await RequestProgram.compile({ cache });
  const withdrawal = await WithdrawalProgram.compile({ cache });
  // `batchReducer.compile()` takes no options; its program's `compile` does, though its type says not.
  const reducer = await (batchReducer.program.compile as (o: { cache: Cache }) => ReturnType<typeof batchReducer.compile>)({ cache });
  const vault = await Vault.compile({ cache });
  return {
    o1js,
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
}
