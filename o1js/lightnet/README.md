# Lightnet tests

Some questions only a chain that checks proofs can answer: a proofs-off chain accepts account updates
the circuit forbids (connector#1554). These tests run against a single-node lightnet,
`o1labs/mina-local-network:4.0.2-devnet` with `PROOF_LEVEL=full`. CI does not run them.

They are the files `src/*.lightnet.ts`. `npm test` skips them, and `npm run test:lightnet` runs only
them. `src/lightnet.ts` connects o1js to the lightnet and lends each test file a funded account.

## Running them

Docker is required. From `o1js/`:

```sh
npm ci
./lightnet/lightnet.sh up      # starts the container, or reuses it, and waits until it is synced
npm run test:lightnet          # proves and sends real commands: several minutes
./lightnet/lightnet.sh down    # removes the container
```

The container is named `zk-toon-lightnet` and listens on 127.0.0.1: the GraphQL API on 8080, the
archive API on 8282 and the account manager on 8181. `lightnet.sh status` says whether it is synced.

A synced chain can still be stuck. The container's SNARK worker can die (`Snark worker died with signal
sigsegv` in `docker logs`) while the daemon keeps producing blocks, and those blocks stay empty, so a
command sits in the pool until o1js gives up with `Exceeded max attempts`. The daemon's prover can also
fail (`Prover failed to prove freshly generated transition` in `docker logs`), and then no block is added
at all: `status` still says synced while the tip's slot stops moving. In either case, `lightnet.sh down`
and `up` start a fresh chain.

## What they show

`rust-land.lightnet.ts` (#36) proves `land` with `zk-prover` alone: o1js builds the command and the Rust
step witness, step proof and wrap proof go in it (the `prove_land` example, built on first use). The chain
applies two in a row, and refuses a real proof of another `land`, which a proofs-off chain would accept.

`ordering-probe.lightnet.ts` (#33) answers this question: in one zkApp command, does an account
update's precondition see the ledger as earlier updates in that command left it? `OrderingProbe.write`
sets a state field and dispatches an action. `OrderingProbe.read` has equality preconditions on that
field and on the action state. Each command calls `write` and then `read`.

| `read`'s preconditions | Result |
| --- | --- |
| new field value, new action state | applied |
| old field value | rejected: `[[["Cancelled"]],[["Account_app_state_0_precondition_unsatisfied"]]]` |
| old action state | applied, see below |
| an action state the account never had | rejected: `[[["Cancelled"]],[["Account_action_state_precondition_unsatisfied"]]]` |

A rejected command is still included in a block, as a failed command: the fee payer pays and nothing
else changes. The tests check that the probe's state is unchanged.

An action-state precondition passes if it matches any of the account's last five action states. A
dispatch in a later slot than the account's previous dispatch shifts those five, so the action state
from before `write` is still one of them. A dispatch in the same slot overwrites the newest one
instead, and then the old state is rejected (LocalBlockchain, whose slot never advances, shows this).
So the old-state result comes from those five states, not from the order of the updates. The order
still matters: the new action state is accepted, and it was none of the five before the command.

For a cursor checked this way, as `collect` would check `reduce`'s `actionCursor` (connector#1553),
this means an action-state precondition alone does not reject a cursor that is up to four dispatch
slots stale.

`vk-ordering.lightnet.ts` (#35) answers this question: does Mina check an account update's proof against a
verification key that an earlier account update in the same command installed? `VkProbeV1` and
`VkProbeV2` have different keys. The zkApp is deployed with V1 and `setVerificationKey: signature`. Each
command holds a signed update that sets V2's key (or none), then a call to `resume`, proved against V1
or V2. V2's `resume` sets `x` to 2.

| Update 1 | `resume` proved against | Result |
| --- | --- | --- |
| sets V2's key | V2 | applied: the account's key hash is V2's and `x` is 2 |
| sets V2's key | V1 | rejected at `safeSend`: `Couldn't send zkApp command: (invalid (Invalid_proof (Pickles.verify dlog_check)))` |
| none (control) | V2 | rejected at `safeSend`: `Couldn't send zkApp command: (invalid (Invalid_proof (Pickles.verify dlog_check)))` |

The ordering holds: the proof is checked against the key the command installed. Both rejections happen
before a block, and the tests check the key and `x` are unchanged afterwards. The control shows the keys
really differ. This confirms the order within a command only. It does not exercise
`impossibleDuringCurrentVersion` and its fallback to `signature` after a hard fork, which a lightnet
can't do. There is no LocalBlockchain counterpart: with proofs off, both circuits get the same dummy key.

## The rogue key pair (#81)

`vault-registry.lightnet.ts` registers vaults through the vault registry (ADR 0011). A 132-character zkApp URI, as
long as an operator's fork-notice location might be, registers and reads back as given.

It then registers a vault whose key is `{ data: <rogue>, hash: <published vault code hash> }`, where the rogue data is
another contract's. The registry's proof checks only the hash, so the command is valid as far as the registry goes.
LocalBlockchain accepts it, and so does this daemon. **The outcome is neither a refusal nor a stuck account:**

| Run, 2026-11-04 | Registration | Key stored | Published vault's `setup` | Rogue contract's `poke` |
| --- | --- | --- | --- | --- |
| Fresh chain, rogue vault first | applied | rogue data, published hash | refused: `Invalid_proof (Pickles.verify dlog_check)` | **applied** |
| After an honest vault registered on the same chain | applied | published hash (data not read) | applied | refused: `Invalid_proof (Pickles.verify dlog_check)` |

On a fresh chain, the rogue contract controls an account that carries the published code hash. The vault's
`editState`, `send` and `editActionState` permissions are `proof`, and a proof of the rogue contract verifies, so it
could move whatever a payer deposits. The vault check compares only the key's hash, so it would pass such a vault.
Which contract the node verifies against depends on what the node has seen, not on the chain's rules. The test runs
the rogue registration first, so on a fresh chain it is the first row: it asserts that the registration applies, that
the stored key is the rogue data under the published hash, and that exactly one of the two contracts' proofs is
accepted. Run again on a chain where an honest vault has registered (its own second test, or `request-fixtures`), the
data assertion may not hold; start a fresh chain first. Its final form has not run yet: the run was stopped for want
of memory.

Why, from Mina's source (`compatible`): a command sent as JSON over GraphQL keeps the key's `data` and `hash` as given
(`verification_key_with_hash` in `fields_derivers_zkapps.ml`). Its binary form carries the data only and recomputes
the hash on receipt (`Verification_key_wire`). So a peer that receives the command by gossip would see the rogue
data's own hash, and the registry's proof wouldn't verify there. That suggests a multi-node network refuses the
command unless a block producer is sent it directly. It has not been run on devnet: this is a single-node lightnet.

## Recording a vault

`npm run request-fixtures` (#67) runs a real vault here, which the tests above do not, and writes the
connector's fixture set (`docs/verification-keys.md`). The run shows what a proofs-on chain asks of a caller:

- A reduce can't use `batchReducer.prepareBatches` as it is: its dummy proof has the wrong domain, and proving
  fails with `Checked.inv` in `scalars_env`. Past 100 pending action lists (`maxUpdatesFinalProof`) it fails
  the same way even with recursion, because the lists the reduce leaves out are proved from that dummy, so a
  vault anyone has pushed past 100 stays stuck. Use `provableBatches` (`src/vault-view.ts`), which proves them
  from a dummy of the action-stack program's domain; `VaultKeeper.reduce` does.
- A deposit and a reduce must land in the slot they name or the next, which here is 40 seconds, and proving
  takes longer. `recorded-vault.ts` names a slot far enough ahead, sends in the slot before it, and rebuilds on a
  miss. A miss fails with `Valid_while_precondition_unsatisfied`, and the fee is still paid. The last run missed
  three times in six such commands.
- The run's deploy doesn't aim yet: it names no slot, so `init` reads the tip's slot, and it lands only if the
  next block is in the following slot. The run retries it, which took 2, 3 and 4 attempts in three runs.

## Aiming a vault deploy at a slot

A vault deploy can aim. `Vault.deploy({ zkappUri, slot })` makes `init` record `slot` as `creationTime` and
require the current slot to be in `[slot, slot + 1]`, the same two-slot range a deposit or reduce uses. A
block before `slot` or more than one slot after it refuses the deploy with
`Valid_while_precondition_unsatisfied`. Without `slot`, `init` takes the network's current slot, as on a
local chain. Land a deploy on a lightnet or devnet by passing the slot your landing helper has chosen,
rather than retrying at the tip's slot or swapping the active Mina instance.
