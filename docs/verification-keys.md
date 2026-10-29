# Published keys and the proofs-on set

Each gate run publishes the circuits' verification keys and the vault's code hash, so a zk edge's
greeting pins (toon-protocol/connector#1511) can be checked against what was deployed. It also runs a
named set of tests with real proofs.

## The published keys

From `o1js/`, after `npm ci`:

```
npm run keys -- <out.json>              # compile with o1js's key cache (~/.cache/o1js)
npm run keys -- --no-cache <out.json>   # compile everything afresh
```

The gate builds the file twice, once with the cache and once with `--no-cache`. It fails unless the
two files are byte for byte identical, then uploads the first as the `verification-keys` artifact of
the CI run. Nothing is committed: the keys change with every circuit or vault change, and the file is
rebuilt from the commit.

The shape is `Keys` in `o1js/src/keys.ts`. Each `verificationKey` is o1js's JSON form: `data` in base64,
and `hash`, a field in decimal.

```json
{
  "o1js": "3.1.0",
  "circuits": {
    "request":      { "name": "zk-toon-request", "methods": ["subsidised", "unsubsidised"], "verificationKey": { "data": "…", "hash": "…" } },
    "withdrawal":   { "name": "…", "methods": ["…"], "verificationKey": { "data": "…", "hash": "…" } },
    "vaultReducer": { "name": "…", "verificationKey": { "data": "…", "hash": "…" } }
  },
  "vault": { "codeHash": "…", "methods": ["…"], "verificationKey": { "data": "…", "hash": "…" } }
}
```

- **The vault's code hash is the hash of its verification key.** A zkApp account holds no code, only
  a verification key, so that key's hash is what names a deployed vault's code. `keys.test.ts` deploys
  a vault and checks that its account carries the published hash.
- **The keys depend on the exact o1js version**, recorded in the file. ADR 0003's pin of the o1js
  version and the key hashes against the Rust prover belongs to the prover (`zk-prover`), not here.
- **The build fails if the vault doesn't compile.** A method that outgrows one circuit (2^16 rows,
  including the check of any proof it verifies) makes Pickles split it into chunks, which the vault's
  other methods don't share, and the compile fails. This is how the reduce's batch size was found to
  be at most 4.

## The proofs-on set

Every other o1js test runs with proofs off. The named set is `PROOFS_ON` in `o1js/src/proofs-on.ts`;
each test uses its entry as its title:

| entry | test | what it proves for real |
|---|---|---|
| `request` | `request.test.ts` | a genesis and a signed request proof |
| `subsidised` | `request.test.ts` | a subsidised request proof |
| `close` | `vault-close.test.ts` | a mutual-close withdrawal proof, then paid at the reduce |
| `escape` | `vault-escape.test.ts` | an escape withdrawal proof, bound to its destination, then finalized |
| `defeat` | `vault-challenge.test.ts` | a request proof that defeats an escape at its next nullifier |
| `vault` | `keys.test.ts` | the vault compiles, and a deployed vault carries the published code hash |

The gate runs `npm test` with vitest's JSON reporter and then `npm run proofs-on -- <report>`, which
fails unless every named test ran exactly once and passed. A test that is skipped, marked todo,
renamed or deleted fails the gate.

In the close, escape and defeat tests the circuit's proof is real and verified against its key, but
the vault transaction itself runs on a local chain with proofs off: proving a vault transaction (the
reduce is near 2^16 rows, and every action needs a reduce) would add minutes per transaction to the
gate. A proofs-on vault transaction is left to the transaction builder against a real network.
