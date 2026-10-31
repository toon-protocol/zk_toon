# The challenger's Mina adapter

`MinaChain` (crate `zk-toon-challenger-mina`, `challenger-mina/`) is the real **vault chain port** of
the challenger. It reads the vault's open escapes through Mina GraphQL and submits defeats and raises
built by the o1js transaction builder (`docs/tx-builder.md`). The decision core (`challenger/`) has no
dependencies and doesn't know about it: this crate depends on the core, not the other way round.

```rust
let graphql = HttpGraphql::new(Endpoints { mina, archive, socks5: Some("127.0.0.1:9050".into()), timeout })?;
let chain = MinaChain::new(Settings { vault, fee_payer, poll }, graphql, tx_builder, request_proofs)?;
```

## Nullifiers

A nullifier crosses the challenger's ports as 32 bytes: the Pallas field element, **little-endian and
canonical** (below the modulus). Bytes at or above the modulus name no nullifier and are refused. It
is the encoding `zk-evidence` uses (`field_to_bytes`), so the evidence port and the chain port name a
state the same way. `nullifier_of_field` and `field_of_nullifier` implement it.

## Reading escapes and their deadlines

An escape's deadline is set by the reduce that records it (a slot after the reduce's `now`, plus the
challenge window, in slots), which the actions don't carry. So the vault's reduce emits an **`escape` event**
for each pending escape it records, raises, finalizes or defeats (`EscapeUpdate` in
`o1js/src/vault.ts`, nine fields: `pending`, then the record's `nullifier, nextNullifier, amount,
conceded, size, destination.x, destination.isOdd, deadline`).

`escapes()` makes two reads:

1. **Daemon** (`VaultState`): the vault's app state, whose field 24 is `pendingEscapesRoot`, and the
   tip's block time, which is "now".
2. **Archive** (`EscapeEvents`): the vault's events, oldest block first, leaving out orphaned blocks
   and failed transactions.

It replays the events into o1js's indexed Merkle map, as the reduce does, and **requires the result
to equal `pendingEscapesRoot`**. Order matters, since a new key takes the map's next leaf. An account
update lists its events newest first (o1js pushes each onto the front), so the adapter reverses each
transaction's run of events back into emission order; if that doesn't rebuild the root, it tries the
archive's order as listed. A lagging, reordered or lying archive is `Unavailable`, never a
missing or invented escape; the challenger retries on its next tick. Open escapes are those pending
with `deadline > now`.

> **Not yet in slots (follow-up to #59).** A pending escape's `deadline` is now a slot (ADR 0007), but
> this adapter still reads "now" as the tip's `utcDate` in milliseconds and `Millis` is the challenger's
> unit, so on a real chain it would see every deadline as long past. It must read the tip's
> `consensusState.slotSinceGenesis` and take its lead time in slots before it runs against a deployed
> vault. The local chain in `tx-builder` answers `utcDate` with the slot, so the tests agree with
> themselves.

## Submitting

`submit_defeat(id)` and `submit_raise(id, to)`:

1. Read the escape afresh. An unknown or closed escape is `Refused`. So is a raise that doesn't
   exceed the concession or exceeds the balance.
2. Take the evidence from the zk edge's recorded request proofs (`RequestProofs`): for a defeat any
   proof at the next nullifier (a subsidised one too, ADR 0001); for a raise the unsubsidised proof
   of the largest tier at the escape's nullifier, which must be at least `to`. The raise claims `to`,
   so the vault lifts the concession to `min(to, b, balance) = to` (ADR 0004).
3. Ask the transaction builder for the transaction and its hash.
4. Send it (`sendZkapp`). A GraphQL error is `Refused` with the daemon's message.
5. **Wait for its outcome.** Each read (`ChallengeStatus`) looks for the hash in the last 290 blocks
   (Mina's frontier) and in the fee payer's pooled commands:
   - in a block with no failure: done;
   - in a block with a failure: `Refused` with the failure;
   - in the pool: read again after `poll`;
   - in neither: sent again (a lost send, or one dropped from the pool), unless the chain time has
     reached the escape's deadline, after which it can't land: `Refused`.

   **A dropped connection or a failed read never ends the wait**: the outcome is read again. A send
   whose answer was lost is waited on the same way, since it may have arrived.

A transaction included more than 290 blocks before a read is not found; the adapter then resends
until the deadline. Polling every few seconds keeps this out of reach except after a long outage.

## Reaching Mina

`HttpGraphql` posts JSON to the two endpoints. With `socks5` set, every request goes through that
SOCKS5 proxy, which resolves the endpoints' host names, and **there is no direct fallback**: if the
proxy is down, nothing is reached.

The transaction builder also reads the vault and fee payer from GraphQL while it builds. Start it with
`--mina <relay>/mina --archive <relay>/archive` from a `Relay` over the same `HttpGraphql`, so its
requests take the same path and it never connects to an endpoint itself.

## Secrets and logs

The adapter logs nothing. Its only secret is the fee payer's key, which goes only to the builder's
stdin and prints as `[secret]`. Errors carry nullifiers and the chain's or builder's messages (the
builder scrubs secrets from its own). Nothing it does links an allowance to the escape beyond what the
vault's public transaction shows.

## Tests

| test | shows |
|---|---|
| `tests/contract.rs` | the port contract suite (`zk_toon_challenger::contract`), over a scripted Mina that answers in the recorded shapes |
| `tests/reading.rs` | the recorded vault (`tests/fixtures/recorded-vault.json`, pinned by SHA-256 in `tests/common/mod.rs`) reads as the escape it holds; an archive that doesn't rebuild the root is `Unavailable` |
| `tests/waiting.rs` | failed polls, a lost send answer, a failed transaction, a lost transaction past the deadline |
| `tests/socks.rs` | direct GraphQL, SOCKS with remote resolution, no fallback when the proxy is down, the builder's relay |
| `tests/local_chain.rs` | a defeat and a raise through the adapter, accepted by the vault on the builder's local chain |
| `tests/encoding.rs` | the nullifier encoding |

The fixture is recorded from the builder's local chain, whose `local.graphql` answers the adapter's
operations in the daemon's and archive's shapes. To re-record it, run
`ZK_TOON_RECORD_VAULT=1 cargo test -p zk-toon-challenger-mina --test local_chain` and pin the new
file's SHA-256.
