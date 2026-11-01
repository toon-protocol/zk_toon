# The devnet smoke test

`npm run devnet -- <run>` (from `o1js/`) deploys a vault to Mina devnet and walks it through #17: deposit,
reduce, request proof, mutual close, escape, and finalize after the challenge window. It pays from the dev
funder, whose key it derives from `TOON_FUNDER_MNEMONIC` and refuses if the address isn't the funder's.

The run's keys and notes are derived from the funder's key, so nothing secret is written down. Its journal,
`docs/devnet-smoke/<run>.json`, holds only public facts: what is done, and each attempt's hash, slots and
timings. Running the command again carries on from the journal. It waits for a command that was out when a
run stopped, and it exits while the escape's window is open, saying when to come back. Set `MINA_GRAPHQL` and
`MINA_ARCHIVE` to use other endpoints.

## Run `smoke-1`, 2026-11-01

**Status: unfinished.** The escape's window runs until slot 932656, about 48 hours after slot 930735, so
finalize, its reduce and the refund can run from about 2026-11-03 21:25 UTC. Then the escape's payout and this
section need updating.

| | |
|---|---|
| Vault | `B62qn8QzkBBkTEhnLYWhyZmAHmpe3SR9UPkeC75MQap9gbiMbJ6C8Bs` |
| Code hash, key hashes | `facts` in `devnet-smoke/smoke-1.json`, with the o1js version |
| Deposits | two of 10 MINA, the smallest size |

| Command | Proving (s) | Send to seen in best chain (s) | Result |
|---|---:|---:|---|
| accounts | 1 | 94 | applied |
| deploy | 1 | 172 | applied in its target slot + 1 |
| setup | 14 | 343 | applied |
| deposit (close's note) | 40 | 78 | applied in its target slot |
| deposit (escape's note) | 9 | 78 | applied in its target slot |
| reduce of the two deposits | 44 | 78 | applied in its target slot |
| mutual close, first | 54 | not timed | **failed:** landed in slot 930706, after its range |
| mutual close, second | 42 | 214 | applied |
| escape | 19 | 82 | applied |
| reduce of the close and the escape | 31 | 82 | applied in its target slot |

"Proving" is the time to build and prove the command, on a 16-core machine that was also proving for another
task. It includes any compile the transaction builder did on first use, which is likely in the first deposit's 40 s.
The request proof took 7 s and verified against the vault's on-chain root.

**Payout so far.** The close of a signed 9.9 MINA state paid the destination exactly 9.9 and the treasury
exactly 0.1, at the reduce.

**Cost so far.** 26.0 MINA left the funder: 20 in deposits, 3 in account creation fees (treasury, destination,
vault), 2 funding the treasury and destination accounts, and 1 in fees (ten commands at 0.1 MINA, the fee this
run chose, including the failed close). A failed command is still charged. 0.1 MINA was enough for every
command, but the run didn't test a lower fee.

## What it showed

- **A range of two slots is tight, and works if the command is aimed.** The vault's deposit and reduce must land
  in slot `t` or `t + 1`. A command in a block before `t` fails and is charged, so the run proves ahead for a
  target slot, then holds the command until a third into the slot before it (`sendPlan` in `o1js/src/devnet.ts`).
  All five aimed commands landed in range at the first try. A wallet or keeper needs the same aiming.
- **Devnet can go quiet for longer than a close's window.** No block landed from slot 930697 to 930706, 13
  minutes. That outlasted the close's 7 slots, and the close failed. A wallet must expect this and prove again.
  This run is too small to say how often that happens.
- **Slot misses surface as `Valid_while_precondition_unsatisfied`.** `currentSlot` is the command's `validWhile`,
  so that, not `Protocol_state_precondition_unsatisfied`, is what the vault's time checks fail with.
- **`batchReducer.prepareBatches` can't be proved on a chain that checks proofs.** Its dummy batch proof has the
  wrong domain, and `Vault.reduce` fails with `Checked.inv … scalars_env`. Use `provableBatches` in
  `o1js/src/vault-view.ts`.
- **`deploy` needs its slot aimed too.** `init` pins the creation slot to what o1js reports as the network's slot,
  which is the tip's and so often already old. The run makes o1js report the target slot while it builds the command.
