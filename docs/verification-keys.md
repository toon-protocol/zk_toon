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
| `landVk` | `land-program.test.ts` | nothing proved: this o1js compiles `zk-prover`'s `land` program to the pinned key |

The gate runs `npm test` with vitest's JSON reporter and then `npm run proofs-on -- <report>`, which
fails unless every named test ran exactly once and passed. A test that is skipped, marked todo,
renamed or deleted fails the gate.

In the close, escape and defeat tests the circuit's proof is real and verified against its key, but
the vault transaction itself runs on a local chain with proofs off: proving a vault transaction (the
reduce is near 2^16 rows, and every action needs a reduce) would add minutes per transaction to the
gate. A proofs-on vault transaction is left to the transaction builder against a real network.

## The request-proof fixtures

The connector's Rust verifier (toon-protocol/connector#1514) is tested against real request proofs,
which the connector cannot make itself (its ADR 0080 forbids o1js), and against what a real vault's
daemon and archive answer. One command makes both, from one commit, about 15 minutes. It needs Docker for
the proofs-on lightnet (`o1js/lightnet/README.md`). From `o1js/`:

```
npm ci
./lightnet/lightnet.sh up
npm run request-fixtures [-- out-dir]   # writes recorded-vault.json and request-proofs.json to test-vectors/request-proofs/
```

It deploys a vault, deposits two notes, reduces, escapes one note, reduces again and records the chain
(`o1js/src/recorded-vault.ts`). Then it proves the requests for the unspent note over that vault's tree.

`recorded-vault.json` holds GraphQL answers as they came:

- `vaultState`: the daemon's `zkappState`, `actionState` and tip slot;
- `actions`: the archive's actions, in the shape `escapeEvents` uses for events;
- `escapeEvents`: the archive's events;
- `named`: `consumedNullifier`, which an escape in the recording consumed, and `absentRoot` and
  `absentNullifier`, which appear nowhere in it.

`request-proofs.json` holds an unsubsidised and a subsidised `RequestProgram` proof (each o1js's
`JsonProof`, its `publicInput` being `RequestPublic`'s fields), the request `verificationKey` (`data` and
`hash`) they verify under, the `vaultCreation` slot the subsidised proof's period counts from, and a real
`zk-toon-withdrawal` proof with its own key, which the request key must refuse. All times are slots.

**The subsidised proof's `requestTime` is a slot the recorded chain has not reached.** A subsidised note
must be 7 days old, which is 6,720 slots, or 37 hours of a 20-second lightnet, and a deposit can't name a
past slot. So that proof is made at `depositTime + 6720`, while the unsubsidised proof is made at the
recording's tip slot. A test of the zk edge's request-time window against the recorded tip can use the
unsubsidised proof only.

Proofs are randomised, so the gate never regenerates them. `npm test` fails if the committed key differs
from the one `RequestProgram` compiles to. `zk-prover/tests/request_proofs.rs` verifies the proofs with
`zk_prover::verify`, and checks without a lightnet that the two files agree: the root is in the recorded
ring, `vault` is the recorded state key, `vaultCreation` is the recorded `creationTime`, both proofs pass
`check_subsidy_period`, and their nullifiers aren't consumed. Rerun the command after any change to the
request circuit or the vault.
