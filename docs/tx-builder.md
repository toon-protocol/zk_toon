# The transaction builder

A Mina zkApp call needs a transaction proof that only o1js can make. The **transaction builder** is
the one place Rust reaches o1js: a Node process that builds and proves vault transactions and request
proofs for the wallet and the challenger.

- The process is `o1js/src/tx-builder-main.ts`, and the operations are in `o1js/src/tx-builder.ts`.
- The Rust client is the `zk-toon-tx-builder` crate (`tx-builder/`). `zk-note` doesn't depend on it.

## Running it

From `o1js/`, after `npm ci`:

```
node --import tsx src/tx-builder-main.ts --mina <graphql url> --archive <archive url> [--proofs=on|off]
node --import tsx src/tx-builder-main.ts --local [--proofs=on|off]
```

| flag | meaning |
|---|---|
| `--mina`, `--archive` | The Mina GraphQL endpoint the vault and fee payer accounts are read from, and the archive endpoint the vault's actions are read from. |
| `--local` | Host an o1js LocalBlockchain in the process and answer the `local.*` operations. The local chain doesn't check proofs, so its transaction proofs are dummies. |
| `--proofs` | `on` (the default) makes real request and withdrawal proofs, and real transaction proofs when the chain checks them. `off` makes dummy proofs, but the circuits and the vault's methods still check every constraint. |

In Rust, `zk_toon_tx_builder::node_command(o1js_dir, &[flags])` returns this command and
`TxBuilder::spawn(cmd)` starts it.

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
| field element, scalar, amount (nanomina), time (ms) | decimal string |
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
{"secret": "<field>", "size": "<nanomina>", "depositTime": "<ms>"}
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
| `depositTime` | the block time the deposit lands at, to within one slot (90 s) |

Result: `{"zkappCommand": {…}}`, the proved and signed transaction as o1js `Transaction.toJSON()`
produces it. It is ready for Mina GraphQL's `sendZkapp`.

### `mutualClose`

| param | |
|---|---|
| `vault`, `feePayer`, `note`, `state` | as above |
| `requestTime` | the close must land within 10 minutes after it |
| `destination` | where the balance goes |
| `clearance` | the zk edge's clearance of this state's nullifier to `destination` |

Result: `{"zkappCommand": {…}, "publicInputFields": [13 decimals]}`. The fields are the withdrawal
proof's public inputs, in the layout `zk_note::withdrawal` documents.

### `escape`

| param | |
|---|---|
| `vault`, `feePayer`, `note`, `state`, `requestTime`, `destination` | as for `mutualClose` |
| `conceded` | what the escape gives up, at most the balance |
| `validUntil` | the last block time the escape may land at, at or after `requestTime` and before the note's expiry |

Result: as for `mutualClose`. `publicInputFields[5]` is the next state's nullifier.

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

`{"proof": <JsonProof>}` → `{"valid": true|false}`: whether the proof verifies against the request
program's verification key, compiled by the builder. Needs `--proofs=on`.

### Local chain operations (`--local` only)

These let tests show that the vault accepts what the builder builds.

| op | params | result |
|---|---|---|
| `local.accounts` | | `{"accounts": [{"publicKey", "privateKey"}]}`, the funded test accounts |
| `local.deployVault` | `stateKey`, `treasury` | `{"vault": <address>}`, deployed and set up |
| `local.submit` | `zkappCommand` | `{}`, or a `rejected` failure |
| `local.reduce` | `vault` | `{}`, after reducing every pending action as a keeper would |
| `local.advance` | `ms` | `{}`, after moving the clock forward at least `ms` |
| `local.now` | | `{"now": <ms>}` |
| `local.balance` | `publicKey` | `{"balance": <nanomina>}` |
| `local.vaultState` | `vault` | the vault's roots, next leaf index, state key and treasury |

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

Defeat and raise (#10, wired up by #15) are added the same way as the others:

1. In `o1js/src/tx-builder.ts`, add an entry to `ops` that reads its params with the shared readers
   (`note`, `noteState`, `feePayer`…), proves inside `proving(…)`, and returns
   `{zkappCommand, publicInputFields}`.
2. In `tx-builder/src/requests.rs`, add the request type with its `to_json`. In `lib.rs`, add a
   method that calls the op and decodes the answer with `Transaction::from_answer`.
3. Document it here.

Pending escapes are not rebuilt from actions, because an escape's deadline depends on when its reduce
landed. A defeat or raise names its pending escape, so it must take the record from its caller, or
the vault must emit it.
