# The transaction builder

A Mina zkApp call needs a transaction proof that only o1js can make. The **transaction builder** is
the one place Rust reaches o1js: a Node process that builds and proves vault transactions and request
proofs for the wallet and the challenger.

- The process is `o1js/src/tx-builder-main.ts`, and the operations are in `o1js/src/tx-builder.ts`.
- The Rust client is the `zk-toon-tx-builder` crate (`tx-builder/`). `zk-note` doesn't depend on it.

## Running it

From `o1js/`, after `npm ci`:

```
node --import tsx src/tx-builder-main.ts --mina <graphql url> --archive <archive url> [--proofs=on|off] [--keys <verification-keys.json>]
node --import tsx src/tx-builder-main.ts --local [--proofs=on|off]
```

| flag | meaning |
|---|---|
| `--mina`, `--archive` | The Mina GraphQL endpoint the vault and fee payer accounts are read from, and the archive endpoint the vault's actions are read from. |
| `--local` | Host an o1js LocalBlockchain in the process and answer the `local.*` operations. The local chain doesn't check proofs, so its transaction proofs are dummies. |
| `--proofs` | `on` (the default) makes real request and withdrawal proofs, and real transaction proofs when the chain checks them. `off` makes dummy proofs, but the circuits and the vault's methods still check every constraint. |
| `--keys` | The file `npm run keys` writes (`docs/verification-keys.md`). With it, the builder finds each vault's generation by its code hash (ADR 0015), uses that generation's values, and refuses a vault whose code hash is in none, naming it. Without it every vault is taken to be the current generation's. |

In Rust, `zk_toon_tx_builder::node_command(o1js_dir, &[flags])` returns this command and
`TxBuilder::spawn(cmd)` starts it. `TxBuilder::set_timeout(Some(d))` bounds how long a request may
wait for its answer: one that runs out kills the process and fails as `io::ErrorKind::TimedOut`, and
every later request fails too, so start a new builder.

## The protocol

Each request is one line of JSON on stdin, and each answer is one line of JSON on stdout. Requests are
answered one at a time, in order. stdout carries nothing but answers: anything o1js prints goes to
stderr.

```json
{"id": 7, "op": "deposit", "params": { ... }}
{"id": 7, "ok": true, "result": { ... }}
{"id": 7, "ok": false, "error": {"kind": "provingFailed", "message": "..."}}
```

`id` is echoed back. It is `null` when the request line couldn't be read.

### Encodings

| value | encoding |
|---|---|
| field element, scalar, amount (nanomina), time (slot) | decimal string |
| public key | base58 address (`B62…`) |
| fee payer private key | base58 (`EK…`) |
| signature | `{"r": <decimal>, "s": <decimal>}`, Mina Schnorr as `zk-note` signs it |

### Shared request parts

`feePayer` names the account that pays the fee and signs. A deposit is also paid from it.

```json
{"privateKey": "EK…", "fee": "100000000"}
```

`fee` defaults to `"0"`.

`note` is what the payer keeps about its deposit:

```json
{"secret": "<field>", "size": "<nanomina>", "depositTime": "<slot>"}
```

`state` is the note's current state. A genesis state has `signed: null`, and its balance is the
deposit size. A signed state carries what the zk edge signed:

```json
{"blinding": "<scalar>", "signed": null}
{"blinding": "<scalar>", "signed": {"balance": "<nanomina>", "prevAnchor": "<field>", "signature": {"r": "…", "s": "…"}}}
```

`prevAnchor` is the previous state's anchor. The builder derives the previous nullifier and this
state's anchor from it.

The builder finds the note in the vault's note tree by its secret's commitment. It rebuilds the tree
and the nullifier set by replaying the vault's reduced actions, and checks both roots against the
vault's state. A note must be reduced before anything can be built from it.

## Operations

### `deposit`

| param | |
|---|---|
| `vault` | the vault's address |
| `feePayer` | pays `size` and the fee |
| `commitment` | `commit_secret(secret)`; the secret itself never crosses the interface for a deposit |
| `size` | one of the vault's deposit sizes |
| `depositTime` | the slot the deposit lands at, to within one slot |

Result: `{"zkappCommand": {…}}`, the proved and signed transaction as o1js `Transaction.toJSON()`
produces it. It is ready for Mina GraphQL's `sendZkapp`.

### `mutualClose`

| param | |
|---|---|
| `vault`, `feePayer`, `note`, `state` | as above |
| `requestTime` | a slot; the close must land within 7 slots (10 minutes, rounded up) after it |
| `destination` | where the balance goes |
| `clearance` | the zk edge's clearance of this state's nullifier to `destination` |

Result: `{"zkappCommand": {…}, "publicInputFields": [13 decimals]}`. The fields are the withdrawal
proof's public inputs, in the layout `zk_note::withdrawal` documents.

### `escape`

| param | |
|---|---|
| `vault`, `feePayer`, `note`, `state`, `requestTime`, `destination` | as for `mutualClose` |
| `conceded` | what the escape gives up, at most the balance |
| `validUntil` | the last slot the escape may land at, at or after `requestTime` and before the note's expiry |

Result: as for `mutualClose`. `publicInputFields[5]` is the next state's nullifier.

### `defeat` and `raise`

A challenge of a pending escape, with a request proof the zk edge recorded as its evidence. Neither
takes a secret but the fee payer's key.

| param | |
|---|---|
| `vault`, `feePayer` | as above |
| `escape` | the escaping state's (current) nullifier, which names the pending escape |
| `evidence` | the request proof's o1js `JsonProof`: at the escape's next nullifier for a defeat, at its nullifier for a raise |
| `claimed` | `raise` only: what the raise claims, in nanomina (ADR 0004); the vault lifts the concession to `min(claimed, b, balance)` |

The builder rebuilds the vault's pending escapes from its `escape` events (`EscapeUpdate` in
`o1js/src/vault.ts`) and checks them against `pendingEscapesRoot`, so the caller passes only the
nullifier. An escape that is not pending is a `badInput` failure; a refusal by the vault (evidence
at the wrong nullifier, a raise that would not increase the concession, …) is `provingFailed`.

Result: `{"zkappCommand": {…}, "hash": "<base58>"}`. `hash` is the command's hash as Mina GraphQL
reports it, so a caller can look its outcome up even when sending it got no answer.

### `requestProof`

An unsubsidised request proof for an allowance. The zk edge is the vault's state key.

| param | |
|---|---|
| `vault`, `note`, `state` | as above |
| `requestTime`, `tier` | public inputs |
| `rerandomBlinding` | the scalar that re-randomises the state's balance commitment |
| `sessionKey` | the allowance's session key |
| `requestExpiry` | bound in the authorization tag |

Result: `{"publicInputFields": [12 decimals], "proof": {…}}`. The fields are `RequestPublic` in
circuit order (`o1js/src/request.ts`):
`[vault.x, vault.isOdd, root, requestTime, tier, nullifier, tag, commitment.x, commitment.y,
subsidised, period, periodNullifier]`. `proof` is the o1js `JsonProof` the zk edge receives.

### `verifyRequestProof`

`{"proof": <JsonProof>, "vaultCreation"?: <slot>}` → `{"valid": true|false}`: whether the proof
verifies against the request program's verification key, compiled by the builder. Given the vault's
`creationTime` as `vaultCreation`, it is also valid only if its period is that vault's
(`subsidyPeriodHolds` in `o1js/src/request.ts`, `RequestPublic::check_subsidy_period` in zk-note): the
circuit can't check that, so a zk edge must. Needs `--proofs=on`.

### The upgrade key's transactions

The upgrade key is a 2-of-3 threshold key (ADR 0012) that nobody holds whole, so the builder can't sign
with it. Each of its two transactions is two operations. **Prepare** builds the transaction unsigned and
answers its full commitment; the share holders sign that commitment (the `upgrade-key` crate) under the
network ID it was prepared for; **attach** puts their signature and the fee payer's in. The builder never
holds a key share. Neither operation needs proofs, and neither compiles anything.

The account update is authorised by signature with the full commitment and no nonce increment (ADR 0006),
so the transaction's replay protection is the fee payer's nonce. Prepare it just before it is signed: a
transaction that lands first moves the nonce and voids it.

| param | |
|---|---|
| `feePayer` (prepare) | `{"publicKey": "B62…", "fee": "<nanomina>"}`: it pays, but isn't asked to sign yet. `fee` defaults to `"0"` |
| `network` | `"testnet"` or `"mainnet"`: the domain the full commitment is signed under. Lightnet, devnet and LocalBlockchain are `"testnet"` |
| `zkappCommand` (attach) | the unsigned command prepare answered |
| `signature` (attach) | the upgrade key's, `{"r", "s"}`, over the full commitment, under the same `network` |
| `feePayer` (attach) | `{"privateKey": "EK…"}`, the key of the fee payer prepare named; it signs for itself |

`prepareDelegation` and `prepareKeyInstall` answer `{"zkappCommand": {…}, "fullCommitment": "<field>"}`.
`attachDelegation` and `attachKeyInstall` answer `{"zkappCommand": {…}}`, ready for `sendZkapp`. Attach is
`badInput` unless the command's fee payer is the key given and exactly one account update wants a signature, with
the full commitment and no nonce increment. It doesn't check the upgrade key's signature: a node refuses a wrong one (another key, another
commitment, the other network), and `local.submit` answers `rejected`.

| op | params | what it does |
|---|---|---|
| `prepareDelegation` | `vault`, `delegate` | sets the vault's delegate. The vault is registry-deployed (ADR 0011), and the upgrade key is its account's key |
| `prepareKeyInstall` | `account`, `verificationKey` | sets the verification key of a zkApp account whose `setVerificationKey` permission is `signature`. `verificationKey` is a key o1js compiled, `{"data": "<string>", "hash": "<field>"}` |

Before a fork the vault's own `setVerificationKey` is `impossibleDuringCurrentVersion`, so a node refuses a
key install on it; installing the vault's own key after a fork is the fork rehearsal (#109). A key install
here is for an account whose permission is `signature`. In Rust: `TxBuilder::prepare_delegation`,
`attach_delegation`, `prepare_key_install` and `attach_key_install`, with `Attachment` taking the
`Prepared` transaction, the signature and the fee payer.

`o1js/src/upgrade-key.lightnet.ts` does both on the proofs-on lightnet, signing with
`cargo run --release -p upgrade-key --features test-utils --example threshold_sign` (`npm run test:lightnet`; the gate
doesn't run it).

### Local chain operations (`--local` only)

These let tests show that the vault accepts what the builder builds.

| op | params | result |
|---|---|---|
| `local.accounts` | | `{"accounts": [{"publicKey", "privateKey"}]}`, the funded test accounts |
| `local.deployVault` | `stateKey`, `treasury` | `{"vault": <address>}`, deployed and set up |
| `local.deployRegisteredVault` | `privateKey` | `{"vault": <address>}`: a vault at that test key's address, deployed through a registry (ADR 0011), not set up |
| `local.deployStandIn` | `privateKey` | `{"account": <address>}`: an account at that test key's address whose `setVerificationKey` is `signature` |
| `local.compileKey` | | `{"verificationKey": {"data", "hash"}}`, a small program's key, compiled by o1js |
| `local.delegate` | `account` | `{"delegate": <address>\|null}` |
| `local.verificationKey` | `account` | `{"verificationKey": {"data", "hash"}\|null}` |
| `local.submit` | `zkappCommand` | `{}`, or a `rejected` failure |
| `local.reduce` | `vault` | `{}`, after reducing every pending action as a keeper would |
| `local.advance` | `slots` | `{}`, after moving the chain forward `slots` |
| `local.slot` | | `{"slot": <slot>}` |
| `local.balance` | `publicKey` | `{"balance": <nanomina>}` |
| `local.vaultState` | `vault` | the vault's roots, next leaf index, state key, treasury and creation time |
| `local.graphql` | `endpoint` (`mina` or `archive`), `request` | the answer to one of the challenger adapter's named GraphQL operations (`VaultState`, `EscapeEvents`, `SendChallenge`, `ChallengeStatus`), shaped as the daemon or archive answers it; a refused send is a GraphQL error |

## Failure answers

| `kind` | when |
|---|---|
| `badInput` | The line isn't a JSON object, the op is unknown, a param is missing or malformed (for example not a decimal, out of range, or not a key), or the vault holds no reduced note with that secret. |
| `provingFailed` | A circuit or a vault method refused the inputs, or proving failed. Examples: the balance doesn't cover the tier, a nullifier is spent, the clearance doesn't verify. The message is o1js's, with secrets removed. |
| `chainUnavailable` | An account or the vault's actions couldn't be fetched, or the rebuilt roots don't match the vault's. |
| `rejected` | `local.submit` only: the local chain refused the transaction. |

After a failure answer the builder keeps answering.

## Secrets

A note's secret, its state's blinding, the re-randomising blinding and the fee payer's private key
reach the builder only in a request, from the caller. The builder:

- keeps them in memory for that request only;
- never logs them and never writes them to disk (o1js caches only compiled keys);
- removes every one of them from a failure message before answering.

In Rust, the types that hold them (`Note`, `NoteState`, `FeePayer`, `RequestProofInput`) print
`[secret]` in place of each one.

## Adding an operation

An operation is added the way `deposit` or `defeat` was:

1. In `o1js/src/tx-builder.ts`, add an entry to `ops` that reads its params with the shared readers
   (`note`, `noteState`, `feePayer`…), proves inside `proving(…)`, and returns
   `{zkappCommand, publicInputFields}`.
2. In `tx-builder/src/requests.rs`, add the request type with its `to_json`. In `lib.rs`, add a
   method that calls the op and decodes the answer with `Transaction::from_answer`.
3. Document it here.

## Pending escapes

Pending escapes can't be rebuilt from actions, because an escape's deadline depends on when its reduce
landed. So the reduce emits an `escape` event for every pending escape it records, raises or finishes,
and the builder (`pendingEscapesView` in `o1js/src/vault-view.ts`) and the challenger's Mina adapter
(`docs/challenger-mina.md`) replay those events, checked against the vault's root.
