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

**State message**:
What the vault signs for a zk note's state: the vault key, the balance commitment and the anchor,
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
