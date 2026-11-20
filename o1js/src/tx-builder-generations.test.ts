// The transaction builder finds a vault's generation by its code hash (ADR 0015) and refuses a code hash in none.
import { describe, expect, it } from 'vitest';
import { Mina, PrivateKey, PublicKey } from 'o1js';
import { createBuilder } from './tx-builder.js';

const call = async (builder: Awaited<ReturnType<typeof createBuilder>>, op: string, params: object) =>
  JSON.parse(await builder.handle(JSON.stringify({ id: 1, op, params })));

describe('the transaction builder and vault generations', () => {
  it('refuses a vault whose code hash is in no generation, naming it', async () => {
    // One builder, so one local chain; the published generations it checks against are changed in place.
    const generations = { mesa: { vault: { codeHash: '12345' } } };
    const builder = await createBuilder({ local: true, proofs: false, generations });
    const [{ publicKey }] = (await call(builder, 'local.accounts', {})).result.accounts;
    const stateKey = PrivateKey.random().toPublicKey().toBase58();
    const { vault } = (await call(builder, 'local.deployVault', { stateKey, treasury: publicKey })).result;
    const codeHash = Mina.getAccount(PublicKey.fromBase58(vault)).zkapp!.verificationKey!.hash.toString();

    // This vault's code hash is in no generation.
    const refused = await call(builder, 'requestProof', { vault });
    expect(refused).toMatchObject({ ok: false, error: { kind: 'badInput' } });
    expect(refused.error.message).toContain(codeHash);

    // In one, it is found, and the request goes on to fail on what it lacks, not on the vault.
    generations.mesa.vault.codeHash = codeHash;
    const found = await call(builder, 'requestProof', { vault });
    expect(found.ok).toBe(false);
    expect(found.error.message).not.toContain('generation');
  }, 120_000);
});
