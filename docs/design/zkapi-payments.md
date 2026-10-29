# zkAPI-style payments on TOON, on Mina

**Status:** Draft design. Nothing here is built. The connector side is specified in
[toon-protocol/connector#1511](https://github.com/toon-protocol/connector/issues/1511). Words in
**bold** on first use are defined in [`GLOSSARY.md`](../../GLOSSARY.md).

## The problem in one paragraph

TOON already hides **what** a payer sends: every packet is a gift wrap sealed to the terminating
connector, so no hop between can read it (connector ADR 0018). It does not hide **who** pays. The first
connector checks an x402 voucher on every packet, and every voucher names the payer's channel. So the
first connector links every packet a payer sends to one channel, and the chain links that channel to
the payer's address. Hops past the first don't learn the payer (ADR 0040), but that only helps while
the first hop and the termination never compare notes.

## The design in one paragraph

Borrow zkAPI's idea and build it on Mina. A payer deposits once into a Mina **vault**, which creates a
**zk note**. It then pays with a zero-knowledge proof that says "some unspent note in this vault can
cover this", without saying which note. A connector that accepts these proofs is a **zk edge**. One
proof buys an **allowance**, a small budget spent with ordinary-looking **session vouchers**. When the
allowance closes, the zk edge charges what was used and signs the note's next state (a **state
advance**). Past the zk edge nothing changes: it pays the next hop with its own ordinary voucher.

```
         proof (no identity)              its own ordinary vouchers
payer ───────────────────────► zk edge ─────────────────────────► hop ──► termination ──► app
  │   session vouchers,          knows: some note paid             (unchanged)  knows: what was
  │   sealed packets             for packets to ILP address X                   asked, not who
  │                              doesn't know: which note, or what was asked
  └── deposit / withdraw ──► Mina vault (public: links an address to *a* deposit, nothing else)
```

**Mina only.** We considered Ethereum with zkAPI's own contracts first. We chose Mina because Mina's
proofs need no trusted-setup ceremony, and because of our relationship with the Mina team. We don't
run a second vault anywhere: two vaults would split payers into two smaller crowds, and privacy
comes from the size of the crowd.

## Two kinds of "circuit"

This word means two different things in TOON, so be careful which one is meant:

- **A zk circuit** is the math program that defines what a proof proves, for example "I own an
  unspent note worth at least `b`". This design is about zk circuits. On Mina they are written in o1js.
- **A Tor or Anyone circuit** is a network path through relays, which hides an IP address. The Anyone
  overlay (toon_cli ADR 0003) does that job here: it hides the payer's and the zk edge's IP addresses.
  It can't do zero-knowledge proofs.

## The pieces, and what each one is written in

| Piece | What it does | Written in | Lives in |
|---|---|---|---|
| **Vault zkApp** | Holds deposits; deposit, mutual close, escape, raise, defeat, expiry sweep (ADR 0005) | o1js. Mina zkApps can only be written in o1js. | this repo |
| **Circuits** | The request proof (with the optional age statement) and the withdrawal proof | o1js | this repo |
| **zk-note primitives** | Domain-separated Poseidon hashes, nullifiers and anchors, balance commitments, the signed state message, the per-period nullifier | Rust (`proof-systems`: curves, Poseidon, hasher, signer) | this repo, used by the connector |
| **Allowances and state advance** | The `zk-note` claim, allowances, the `ZkNoteVault` port, who pays a charge | Rust | connector, #1511 |
| **Payer wallet** | Deposits, keeping the note secret and states, proving, running allowances, exits | Rust, with o1js only for proving | toon-client / `toon` CLI |
| **Challenger** | Watches the vault and defeats or raises dishonest escapes from the zk edge's evidence | Rust | this repo |

The vault and circuits have to be o1js. Everything that only **checks** or **signs** can be Rust,
apart from the one gap below.

## How a payment works

### 1. Deposit (once, public)

- The payer deposits one of a few **fixed sizes** of MINA, with a commitment to a secret only it knows.
  The note records its deposit time and lives 180 days.
- To deposit a balance that isn't one of the sizes, the wallet **splits** it into several notes, like
  making change, and spreads the deposits out over time. A swap made right before a deposit, or
  leftover change at the depositing address, would link the payer to the note.
- This is the only step tied to the payer's address.

### 2. Open an allowance (one proof)

- The payer makes a fresh session key and a request proof at its note's current state.
- The proof's authorization tag binds this zk edge, the session key, the tier `b` and the expiry, so
  the proof can't be replayed anywhere else.
- The zk edge checks, cheapest first:
  1. `b` is a published tier;
  2. the tag binds;
  3. the root is one the vault has held;
  4. the nullifier is unseen;
  5. the proof verifies.
- It then records the nullifier and the proof as evidence before it answers.

### 3. Send packets

Each packet carries a session voucher instead of a channel voucher. The rules are the same as for
any voucher at the client edge: the amount only goes up, each step meets the price, and the total
is at most `b`. A packet whose forward the next hop rejects comes off the charge.

### 4. Close the allowance (state advance)

- The zk edge charges `Δ` (the net amount used) and signs the next state at the anchor derived from
  the spent nullifier.
- It never learns the note's balance: the balance commitment can be reduced by `Δ` without being
  opened.
- A TOON price is fixed before a packet leaves, so `Δ` is known exactly. Unlike zkAPI, there is no
  waiting for a provider to report usage.

### 5. Withdraw (public)

- **Mutual close:** the zk edge co-signs and the payer gets its balance at once.
- **Escape:** if the zk edge won't co-sign, the payer exits through the vault alone, after the
  challenge window, giving up at most one allowance (`b`).

## Subsidised allowances: rewarding notes for staying

The crowd only grows if notes stay unspent for a long time. So each zk edge may set a **subsidy
budget**. Once per **subsidy period**, a note at least 7 days old may open one **subsidised
allowance**: an allowance of the smallest tier whose charge the subsidy budget pays, not the note.
The reward is service, never money ([ADR 0001](../adr/0001-a-notes-reward-is-service-not-money.md)).

| Rule | Value |
|---|---|
| **Note age** | Time since deposit, read from the deposit time stored in the note. Spending doesn't reset it. |
| Minimum age | 7 days |
| Subsidy period | 7 days, counted in whole weeks from the vault's creation, the same for everyone |
| Claims | One per note per period, enforced by a per-period nullifier that can't be linked across periods |
| Size | The smallest tier only |
| Budget | Set by each zk edge, may be zero. When it is spent, requests are refused with their own reason. The greeting shows only "open" or "closed". |
| Personhood check | None at launch |
| Reporting | The self-description publishes how many subsidised allowances were granted in each **finished** period, never the current one |

**In the escape rules,** a subsidised proof can never raise a concession, though it can still
defeat a stale escape. Without this, a zk edge could withhold the next state and charge the note for
an allowance the subsidy was meant to pay.

## What each party learns

| Party | Who paid | What was asked | Which packets go together |
|---|---|---|---|
| **zk edge** | No, only that some note at a known root has `B ≥ b` | No (gift wrap) | Packets within one allowance. Different allowances can't be linked. |
| **Later hops** | No (unchanged) | No (unchanged) | Only what they already see |
| **Termination and app** | No. The app gets no `X-TOON-Payer`, even on a one-hop path. | Yes | Only through content or timing |
| **Chain observer** | Deposits and withdrawals, not traffic | No | No |

**What still leaks:**

- the timing and volume of allowances;
- the tier chosen;
- the destination ILP address of each packet, which the zk edge must see to route;
- whether an allowance is subsidised, which reveals a note at least 7 days old;
- the last allowance before an escape.

**The anonymity set** is the unspent notes of the same size in one vault, owned by different people.
It starts at zero: Mina has no live privacy pool to share
([research](../research/mina-privacy-pool-landscape.md)). Count it as independent holders, not as
notes.

## Building it on Mina

- **No trusted setup.** Mina's proof system (Kimchi, with Pickles for recursion) needs no ceremony.
  That removes zkAPI's main blocker.
- **On-chain state.** Mesa (on mainnet since September 2026) gives a zkApp 32 on-chain fields. The
  vault keeps three things on chain:
  - the note tree's root;
  - the root of the nullifier set, an o1js `IndexedMerkleMap`, which can prove a nullifier is unspent;
  - a short ring of recent roots, so "a root the vault has held" needs no archive node.
- **Signatures.** The zk edge signs states with Mina Schnorr through Rust `mina-signer`. Inside a
  proof, o1js always checks signatures under the **devnet** network ID, so the zk edge signs with
  that ID even for a mainnet vault. A shared test vector pins this rule.
- **The one gap: checking proofs in Rust.**
  - The connector must check request proofs without running o1js (connector ADRs 0002 and 0065-mina).
  - The only Rust verifier for Mina proofs is in the Mina Rust node. o1Labs paused that node in July
    2026, and its public function only takes zkApp transactions, not our proofs.
  - So the first spike is to fork or vendor that verifier and expose the generic verify path, then
    test it against o1js 3.x proofs. If that fails, the fallback is an o1js helper process, which
    would need a new ADR overturning ADR 0002 on purpose.
- **Asset.** The vault holds MINA. No stablecoin is live on Mina, and DEX liquidity is a few thousand
  MINA, so the zk edge carries the price risk of paying downstream hops in USDC. That conversion uses
  the declared rate of connector ADR 0071.

## Trust and money

- **The payer** risks at most one allowance (`b`) if the zk edge misbehaves.
- **The zk edge operator** pays downstream hops at once but is paid only when notes close. Its
  exposure is capped by the configured total of open allowances. It also pays its subsidy budget.
  It needs a live challenger.
- **Nobody else** changes what they trust.

## Rejected alternatives

- **Ethereum with zkAPI's vault.** zkAPI's code already exists there, but it needs a trusted-setup
  ceremony, and we chose Mina (above).
- **Both chains.** Rejected because it splits the crowd.
- **Proofs at every hop.** Peers are known operators, so their identity isn't the secret. Proving at
  every hop only adds cost.
- **One proof per packet.** zkAPI states are strictly one at a time, and each proof costs seconds.
  Allowances keep sessions unlinkable to each other at a fraction of the cost.
- **A tradeable token, or MINA rewards, to grow the crowd.** See ADR 0001 and
  [the token research](../research/token-distribution-and-the-vault.md).

## Phases

0. **Primitives and parity.** The Rust zk-note primitives, plus test vectors produced by o1js
   (Poseidon, generators, Schnorr under the devnet ID). The Rust verifier spike.
1. **Vault and circuits on Mina devnet.** Deposit, request proof (with the age statement), mutual
   close, escape, raise and defeat, on a vault with fixed MINA sizes.
2. **zk edge on devnet.** #1511 in the connector, a payer wallet in the `toon` CLI, and the challenger.
3. **Subsidised allowances.** The per-period nullifier, the charge paid by the subsidy budget, and
   reporting for finished periods.
4. **Mainnet gates.** External review of the vault and circuits, enough independent holders that
   the crowd means something, and a stablecoin decision.

## Open questions

1. **Who runs the first zk edge:** the devnet relay hub, or a dedicated node?
2. **Fixed deposit sizes and tiers:** which values? They set the crowd per size and the payer's
   worst-case loss.
3. **Rust verifier:** fork the paused Mina Rust node's verifier, or ask o1Labs to publish one?
4. **Stablecoin:** when, if ever, does the vault hold something other than MINA?
5. **Relationship to upstream zkAPI:** we reuse its design, not its code. Do we tell its authors?
