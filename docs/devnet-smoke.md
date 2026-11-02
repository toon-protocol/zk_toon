# The devnet smoke test

`npm run devnet -- <run>` (from `o1js/`) deploys a vault to Mina devnet and walks it through #17: deposit,
reduce, request proof, mutual close, escape, and finalize after the challenge window. It pays from the dev
funder, whose key it derives from `TOON_FUNDER_MNEMONIC` and refuses if the address isn't the funder's.

The run's keys and notes are derived from the funder's key, so nothing secret is written down. Its journal,
`docs/devnet-smoke/<run>.json`, holds only public facts: what is done, and each attempt's hash, slots and
timings. Running the command again carries on from the journal. It waits for a command that was out when a
run stopped, and it exits while the escape's window is open, saying when to come back. Set `MINA_GRAPHQL` and
`MINA_ARCHIVE` to use other endpoints.

`npm run devnet -- short-<name> --short-window` is a test run: its vault's challenge window is 2 slots, and the
run waits it out. The script refuses a `short-` name without the flag and the flag without the name, a window
other than the one in the run's journal, and a vault that holds another window on chain. A journal that deployed
before windows were recorded counts as the published window.

## Run `short-1`, 2026-11-02: the escape pays out, on a short-window test vault

**This is a short-window test vault, not the published policy.** Its challenge window is 2 slots, not 1,920, so
no challenger had a realistic time to answer and the 2-day wait itself wasn't exercised. No defeat or raise was tried.

**Its verification keys are the published ones.** The plan expected different keys, and that turned out to be
wrong. `init` isn't a proved method: it runs inside the signed deploy, and `reduce` reads the window from state.
So only the deploy differs (`deployWithWindow` in `o1js/src/devnet.ts`). The account's on-chain verification key
hash is the published vault code hash, and the proofs on chain are the published circuits'.

| | |
|---|---|
| Vault | `B62qjFXFC2hvmf1WgrffgfZE5933FoZd4hu7vkDDKNFhhcaNQ4m2L4y` |
| Challenge window on chain | 2 slots (state field `challengeWindow`, read back from the account) |
| Code hash, key hashes | `facts` in `devnet-smoke/short-1.json`, with the o1js version |
| Deposits | two of 10 MINA, the smallest size |

| Command | Proving (s) | Send to seen in best chain (s) | Landed in slot | Result |
|---|---:|---:|---:|---|
| accounts | 1 | 229 | 930922 | applied |
| deploy | 1 | 82 | 930925 | applied in its target slot |
| setup | 9 | 163 | 930927 | applied |
| deposit (close's note), first | 28 | 341 | 930933 | **failed:** target 930930, no block until after its range |
| deposit (close's note), second | 6 | 82 | 930934 | applied in its target slot |
| deposit (escape's note) | 6 | 82 | 930937 | applied in its target slot |
| reduce of the two deposits | 24 | 82 | 930940 | applied in its target slot |
| mutual close | 18 | 244 | 930943 | applied |
| escape | 14 | 341 | 930947 | applied |
| reduce of the close and the escape | 29 | 82 | 930950 | applied in its target slot, deadline 930953 |
| finalize | 7 | 278 | 930956 | applied |
| reduce of the finalize | 21 | 180 | 930960 | applied in its target slot + 1 |
| refund | 2 | 50 | 930961 | applied |

"Proving" is measured as for `smoke-1` below. The request proof took 8 s and verified against the vault's on-chain
root. The whole run took about 63 minutes.

**Payouts,** read from the balance changes of the commands in the best chain, not from the script's own reads:

| Command | Vault | Destination | Treasury |
|---|---:|---:|---:|
| reduce of the close (signed state of 9.9) | -10 | +9.9 | +0.1 |
| reduce of the finalize (genesis state, concession 0.01) | -10 | +9.99 | +0.01 |

**Costs.** The funder went from 272.8 to 268.5 MINA, a net cost of **4.3 MINA**: 3 in account creation fees
(treasury, destination, vault) and 1.3 in fees (13 commands at 0.1 MINA, including the failed deposit). Before the
refund 26.2 MINA had left it: 20 in deposits, 2 funding the treasury and destination, and those 4.2 in costs (12
commands). The refund returned **22.00 MINA** exactly (20.89 from the destination, 1.11 from the treasury) for its own
0.1 fee. The vault, the treasury and the destination all hold 0 now.

### What `short-1` showed

- **The close's and escape's slot arithmetic holds on a chain that checks proofs.** The reduce at `now` = 930950
  recorded the deadline 930953 (`now + 1 + window`), finalize was sent at that slot, and the escape paid at the
  following reduce.
- **A vault's code hash doesn't name its challenge window.** _Contradicts ADR 0007, "These constants are part of the
  verification key", for the challenge window; worth reopening._ The window is state the deployer writes in the
  signed deploy, and this vault shows a window of 2 under the published code hash. So a zk edge or payer pinning
  the code hash alone would accept this vault, and it must read `challengeWindow` too (toon-protocol/connector#1511).
  The other state `init` writes is set the same way (inferred from the code, not tried on devnet).
- **An aimed command can still miss.** Six of the seven aimed commands landed in range. The first deposit was
  sent in time, and no block came between slots 930927 and 930933, past its range. It was charged and proved again.
- **Empty blocks happen with commands waiting.** Slots 930951 to 930953 had blocks with no command.
  The finalize, sent at 930953, landed in 930956. Inclusion here is small-sample evidence: one run, 13 commands.

## Run `smoke-1`, 2026-11-01

**Status: unfinished, by decision.** Its escape was recorded with a deadline of slot 932656 and was not finalized:
the escape's payout was shown by `short-1` instead. Finalize, its reduce and the refund were not run. As read on chain
on 2026-11-02, its 10 MINA escape note is still in the vault, and 10.9 and 1.1 MINA are still in its destination
and treasury accounts. All are left on devnet.

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

## What `smoke-1` showed

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
