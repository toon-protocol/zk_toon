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
The span of time in which each zk note may claim at most one subsidised allowance.
_Avoid_: Epoch, round, claim window

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
