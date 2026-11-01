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
command sits in the pool until o1js gives up with `Exceeded max attempts`. `lightnet.sh down` and `up`
start a fresh chain.

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
