# zk_toon

Payments on TOON that hide which payer paid. A payer deposits into a Mina vault once, then pays a
zk edge with zero-knowledge proofs instead of vouchers that name its channel.

## Language

### Notes and the vault

**Vault**:
The Mina zkApp that holds every note's deposit and pays it back out on withdrawal.
_Avoid_: Pool, mixer, contract (unqualified)

**zk note**:
One deposit in the vault, spendable only by whoever knows its secret, and carrying a balance that
only its holder can see.
_Avoid_: Channel, account, coin

**Note age**:
The time since a zk note was deposited. It doesn't reset when the note spends.
_Avoid_: Holding time, idle time, time since last spend

**Balance commitment**:
A hiding commitment to a zk note's balance, `B·G + r·H` on Pallas, that its holder can re-randomise
or charge without opening it.
_Avoid_: Encrypted balance, hidden balance

**State key**:
The Mina public key the zk edge signs states and clearances with, and the vault accepts them from.
It isn't the vault's own address.
_Avoid_: Vault key, edge key, signing key (unqualified)

**State message**:
What the zk edge signs for a zk note's state: the state key, the balance commitment and the anchor,
signed under the devnet network ID for every vault.
_Avoid_: Receipt, checkpoint

**State advance**:
The zk edge signing a zk note's next state after charging it, without learning its balance.
_Avoid_: Settlement, landing

### Paying a zk edge

**zk edge**:
A connector that accepts payment from zk notes and runs the vault's off-chain side.
_Avoid_: On-ramp, mixer, zk node

**Allowance**:
A short-lived budget, bought with one proof, that a payer spends with session vouchers.
_Avoid_: Lease, session, credit line

**Session voucher**:
A cumulative amount against one allowance, signed by that allowance's throwaway session key.
_Avoid_: Claim (unqualified), receipt

**Subsidised allowance**:
An allowance whose charge is paid from the zk edge's subsidy budget instead of by the note that
opened it.
_Avoid_: Holding credit, free allowance, loyalty reward, anonymity mining

**Subsidy budget**:
What a zk edge chooses to spend, each period, on paying for subsidised allowances. It may be zero.
_Avoid_: Treasury, rewards pool, incentive fund

**Subsidy period**:
The span of time in which each zk note may claim at most one subsidised allowance. Periods are whole
weeks counted from the vault's creation time. A subsidised request proof publishes its period, and
the zk edge checks it against the vault's creation time and the proof's request time.
_Avoid_: Epoch, round, claim window

**Per-period nullifier**:
The value a subsidised request proof publishes so a zk edge can refuse a second claim by one note in
one subsidy period: derived from the note's secret, index and period, so it is the same for every
state of the note within a period and different in the next.
_Avoid_: Claim nullifier, subsidy tag

**Charge**:
What an allowance actually cost the zk note that opened it, known when the allowance closes. It is
at most the allowance's tier.
_Avoid_: Δ (in prose), usage, spend

### Evidence

**Evidence file**:
The zk edge's append-only record of every allowance it granted and how each one closed, which the
challenger reads.
_Avoid_: Proof log, journal (that's the connector's own record)

**Grant record**:
An entry in the evidence file for one granted allowance: its request proof and the allowance's
terms, written before the allowance is granted.
_Avoid_: Proof record, allowance record

**Close record**:
An entry in the evidence file giving an allowance's charge, written when its zk note's state
advances.
_Avoid_: Settlement record, charge record

**Evidence hash**:
The hash that names one record in the evidence file. The connector's journal stores it in place of
the record.
_Avoid_: Proof hash, record id

### Leaving the vault

**Mutual close**:
Leaving by agreement: a payer withdraws a zk note's balance with the zk edge's clearance, without
a challenge window.
_Avoid_: Cooperative exit, withdrawal (unqualified)

**Clearance**:
The zk edge's signature, under the state key, agreeing that one state's nullifier may close to one
destination.
_Avoid_: Co-signature, release, approval

**Escape**:
Leaving without the zk edge: a payer consumes a zk note's current and next nullifiers, names a
concession and a destination, and is paid after the challenge window unless the escape is defeated.
_Avoid_: Forced exit, unilateral close, emergency withdrawal

**Concession**:
What an escape gives up of its balance to the treasury: named by the payer, at most the balance,
and liftable by a raise to at most one allowance's tier.
_Avoid_: Penalty, fee, Δ (in prose)

**Challenge window**:
The 2 days after the vault records an escape, during which a challenger may defeat or raise it.
Only after it ends can anyone finalize the escape.
_Avoid_: Dispute period, timeout

**Defeat**:
Cancelling an escape, within its challenge window, with a request proof at its next nullifier: the
note's successor state already opened an allowance, so the escape was from a stale state. Nothing is
paid and the deposit stays in the vault. The escape consumed both nullifiers, so the note goes on from
the state the zk edge signs after that successor.
_Avoid_: Cancel (unqualified), slash, veto

**Raise**:
Lifting an escape's concession, within its challenge window, to `min(claimed, b, balance)` with a
request proof of tier `b` at its current nullifier, where `claimed` is the allowance's recorded charge
or `b` if it never closed. Refused unless it increases the concession, and never from a subsidised
proof.
_Avoid_: Penalty, top-up, dispute

**Ownership proof**:
A proof, shown only to the zk edge, that the payer holds a zk note's current state. The vault
refuses it.
_Avoid_: Ownership withdrawal, identity proof

**Treasury**:
The zk edge operator's address, which receives what a closed or expired note's balance leaves of its
deposit.
_Avoid_: Subsidy budget, fee address

### Building transactions

**Transaction builder**:
The o1js process that builds and proves vault transactions and request proofs for callers in Rust,
which send it a note's secrets and get back a transaction ready to send or a proof.
_Avoid_: Prover sidecar, o1js bridge

### Building and publishing

**Published keys**:
The verification keys of the request proof, the withdrawal proof and the vault's batch reducer, with
their hashes and the vault's code hash, that each build writes and the gate uploads. A zk edge's
greeting pins are checked against them.
_Avoid_: VK dump, key bundle

**Vault code hash**:
The hash of the vault's verification key: the key a deployed vault account carries, and so the only
thing that names its code on chain.
_Avoid_: Contract hash, bytecode hash

**Proofs-on set**:
The named tests that compile the circuits and prove for real: the request proof, the subsidised proof,
mutual close, escape, defeat and the vault's compile. The gate fails unless each ran and passed.
_Avoid_: Slow tests, integration tests
