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
   tip's `slotSinceGenesis`, which is "now".
2. **Archive** (`EscapeEvents`): the vault's events, oldest block first, leaving out orphaned blocks
   and failed transactions.

It replays the events into o1js's indexed Merkle map, as the reduce does, and **requires the result
to equal `pendingEscapesRoot`**. Order matters, since a new key takes the map's next leaf. An account
update lists its events newest first (o1js pushes each onto the front), so the adapter reverses each
transaction's run of events back into emission order; if that doesn't rebuild the root, it tries the
archive's order as listed. A lagging, reordered or lying archive is `Unavailable`, never a
missing or invented escape; the challenger retries on its next tick. Open escapes are those pending
with `deadline > now`.

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

## Running the challenger

The crate's binary, `zk-toon-challenger`, is the challenger as a service. It wires the decision core
to `MinaChain`, the zk edge's evidence file (`FileEvidence`) and a journal file (`FileJournal`), and
makes one pass every `--interval`:

```sh
ZK_TOON_FEE_PAYER_KEY=EK… zk-toon-challenger \
  --vault B62… --mina https://…/graphql --archive https://…/graphql \
  --evidence /var/lib/zk-edge/evidence --journal /var/lib/zk-challenger/journal --o1js ./o1js
```

| flag | default | |
|---|---|---|
| `--vault`, `--mina`, `--archive` | required | the vault and the two GraphQL endpoints |
| `--evidence` | required | the zk edge's evidence file, read as it grows |
| `--journal` | required | created if missing; keep it across restarts |
| `--o1js` | required | the o1js package (`npm ci` done) that runs the transaction builder |
| `--socks5` | none | reach both endpoints, and the builder, through this proxy only |
| `--fee` | 100000000 | nanomina per defeat or raise |
| `--min-lead` | 40 | the fewest slots before a deadline at which it still submits (an hour at 90 s slots) |
| `--interval`, `--poll`, `--timeout` | 60, 10, 30 | seconds between passes, between reads of a sent transaction, per request |
| `--builder-timeout` | 900 | seconds one request to the transaction builder may take; past it the builder is stopped and the service exits |

The fee payer's key is read only from `ZK_TOON_FEE_PAYER_KEY`, never from a flag, so it doesn't show
in a process listing. A bad flag or key stops it at once with exit status 2.

The builder runs with proofs on, started through a `Relay`. It also verifies each recorded request
proof before the core acts on it: its `vault` input must be the vault's state key (read from the
vault's state at start), and the proof must verify against the request proof's verification key. A
proof made for another vault therefore raises `alarm … evidence-invalid` rather than a refused
submission on every pass, and a defeat or raise only ever carries a proof that verified. A pass reads the
chain time (the tip's slot, `MinaChain::now`) and ticks the core (`zk_toon_challenger::service::pass`).
Then it prints one line per report to stdout:

| line | |
|---|---|
| `seen <nullifier>` | an escape it hadn't seen before |
| `submitted <nullifier> defeat` / `… raise <nanomina>` | a defeat or raise that landed |
| `submit-failed <nullifier> <action>: refused: …` / `…: unavailable: …` | the vault, the chain or the builder refused it, or it couldn't be sent; the next pass decides again |
| `alarm <nullifier> evidence-invalid` | recorded evidence that doesn't verify or doesn't make sense; nothing submitted |
| `alarm <nullifier> deadline-too-close <slots>` | too close to the deadline to act safely; nothing submitted |
| `evidence-unavailable <nullifier>` | the evidence file couldn't be read; retried next pass |
| `unavailable: …` / `refused: …` | the chain or the journal couldn't be read; the whole pass is retried next interval |

A nullifier prints as 64 hex digits, in the port's encoding. A pass takes the escapes nearest
deadline first, since each submission waits for its outcome. A pass never stops the service. A chain
or journal that can't be read is logged, and the next pass reads everything again. After a restart,
the journal stops it from repeating an action, and reading the chain afresh means it misses no
escape. If the builder's process becomes unreachable (it died, or answered out of turn), the service
exits with status 2 after the pass, so run it under a supervisor that restarts it (systemd's
`Restart=always`). The builder's own output (o1js) goes to stderr.

A pass reads the chain time again after each submission, since each waits for its outcome, so a
later escape's `--min-lead` is measured from when the pass reaches it. A builder request that takes
longer than `--builder-timeout` stops the builder, and the service exits as for a builder that died.

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
| `tests/options.rs` | the service's flags and defaults, the fee payer's key taken only from the environment, and every flag in the usage and in this page |
| `tests/reading.rs` (chain time, state key) | `now` is the recorded tip's slot; `state_key` is the key the recorded vault was set up with |
| `tests/verifier.rs` | a proof whose `vault` input isn't the state key doesn't verify, and the proof verifier isn't asked |

The fixture is recorded from the builder's local chain, whose `local.graphql` answers the adapter's
operations in the daemon's and archive's shapes. To re-record it, run
`ZK_TOON_RECORD_VAULT=1 cargo test -p zk-toon-challenger-mina --test local_chain` and pin the new
file's SHA-256.
