<!--
TOON profile. Everything above the marker line is TOON's and is not proposed upstream. Everything
below it is the text proposed to x402-foundation/x402 as
specs/schemes/batch-settlement/scheme_batch_settlement_mina.md (connector#1562).
-->

# TOON profile: the Mina binding of x402 batch-settlement

> **Draft.** This is the binding TOON builds to. It is not merged upstream, and TOON does not wait
> for it to be (connector#1558). Proposing it upstream is public and needs the owner's go-ahead at
> the time (connector#1562).

**Where the decisions come from.** Each rule below the marker comes from a ticket on the map
"Mina returns as a settlement chain" (connector#1548). The detail and the evidence are in those
tickets and their research notes, not here:

| Topic                                                        | Decided in                    | Research note (in `toon-protocol/connector`)          |
| ------------------------------------------------------------ | ----------------------------- | ----------------------------------------------------- |
| Voucher, ids, tags, amounts, time, delay bounds, roles       | connector#1552                | `docs/research/mina-x402-binding-answers.md`          |
| One shared account, actions, reducer, pulled payouts         | connector#1553                | (the ticket's resolution comments)                    |
| Permissions, the upgrade key, `resume`, the pinned VK        | connector#1559                | `docs/research/mina-zkapp-upgrades-across-forks.md`   |
| Landed, counted, `valid_until`, fees                         | connector#1560                | `docs/research/mina-settlement-confirmation-and-fees.md` |
| A TOON-owned binding of x402's outline, proposed upstream    | connector#1558                | `docs/research/mina-x402-batch-settlement.md`         |

**What TOON implements of it.**

- **Self-managed only, and no facilitator.** Each connector proves and submits its own commands
  and pays their fees from its Mina settlement key (`[settlement.mina.key]`). The optional
  facilitator below is specified for x402's sake; TOON does not run one.
- **On a node's own channels one key plays every role:** `payer`, `payerAuthorizer`, `receiver`,
  `receiverAuthorizer` and `payTo` (ADR 0075 decision 3).
- **Peers only.** A Mina voucher is accepted on a peer carriage, on a bound channel. The client
  edge still refuses `blockchain: "mina"` by name.
- **Operational figures**, which are TOON's choices, not the binding's:
  - *Landed* means included with an empty `failureReason`. *Counted* means the dispatch is 15
    blocks deep. Only counted collateral backs vouchers.
  - Every command carries `valid_until` = current slot + 20.
  - The fee starts at 0.1 MINA and doubles after 3 blocks without inclusion, up to 1 MINA.
  - Vouchers on open channels are landed every 24 hours. The default `withdrawDelay` is one day
    and the floor TOON accepts is one day.
  - The connector rebuilds the channel map from an untrusted `archive_url` and checks it against
    the on-chain action state and root.
- **Not proposed upstream:** TOON's claim-state challenge (tag `x402-mina-challenge*`, ADR 0075
  decisions 5–6) and the wire vectors (`vectors/wire-vectors.json`, schema 9), which pin this
  binding's bytes for TOON's SDKs.

**Chosen in this draft, for review.** Three spellings no ticket fixed: `asset` is native MINA's
base58 token id (D7 left the upstream spelling open; TOON's own greeting keeps `slip44:12586`),
`networkId` is `0` devnet / `1` mainnet (Mina's signer ids), and `deposit.transaction` is o1js
`Transaction.toJSON()`. The vectors pin whichever stands.

**Still open, and owned elsewhere.** The zkApp's address and VK hash per network (zk_toon#26), the
map height and batch size (zk_toon#26), recursion in the Rust prover (zk_toon#32), and precondition
ordering within one command (zk_toon#33). The spec text says where each lands.

<!-- ======================== upstream text below this line ======================== -->

# Scheme: `batch-settlement` on `Mina`

## Summary

The `batch-settlement` scheme on Mina is a **capital-backed** network binding. It uses
unidirectional payment channels held by one zkApp, in the native MINA token. Clients deposit into
a channel once and sign off-chain **cumulative vouchers** per request. Servers verify each voucher
with one Schnorr signature check and land them on chain at their own pace.

It follows the [EVM binding](./scheme_batch_settlement_evm.md): the same roles, the same
cumulative voucher, the same two-step timed withdrawal and the same signed cooperative refund. It
departs where Mina differs:

- **There is no `msg.sender`.** Every authorization is either a signature checked inside the
  zkApp's proof or a signed account update from the authorizing account.
- **Every channel transaction is a zkApp command with a proof.** The prover is whoever submits:
  the client, the server, or an optional facilitator. A proof is checked against the zkApp's
  verification key, not against its prover, so anyone may prove a command a party has authorized.
- **Claim and settle are one operation.** A claim records the new `totalClaimed` and credits the
  receiver in the same reduction. The credit is collected with `collect`. There is no
  per-receiver accumulator across channels (see [Claim and settle](#claim-and-settle)).
- **Methods dispatch actions; a reducer applies them.** All channels share one zkApp account. Its
  methods only append actions, and a permissionless `reduce` folds them, in order, into a Merkle
  map of channel leaves. This lets many channels' transactions land in the same block without
  conflicting.
- **Time is the global slot.** Every time check uses the slot of the including block. The
  withdraw delay is configured in seconds and converted to slots inside the circuit.

The scheme supports **dynamic pricing**: the client authorizes a maximum per request, and the
server charges the actual cost within that ceiling.

This binding defines **self-managed** voucher management only (`extra.voucherManager` omitted or
`"server"`). Facilitator-managed mode is not defined for Mina in this version.

---

## Conventions

### Fields, hashes and tags

- A **field** is an element of the Pallas base field (about 2²⁵⁴). Every hashed or signed value
  in this binding is a list of fields.
- **Poseidon** is Mina's Poseidon over the Pallas base field (the kimchi parameters used by Mina's
  protocol).
- **`hashWithPrefix(tag, xs)`** absorbs the tag as **one field** first, permutes, then absorbs
  `xs`. This is o1js `Poseidon.hashWithPrefix` and Rust `mina-hasher`'s `Hasher::init(domain)`.
  It is **not** `Poseidon.hash([tagField, ...xs])`, which gives a different digest.
- **Every tag is exactly 20 ASCII bytes**, padded with `*`. o1js pads a short tag with zero
  bytes and Mina's OCaml and Rust pad with `*`, so a tag shorter than 20 bytes hashes differently
  across implementations. The tags are:

  | Tag                    | Hashes                               |
  | ---------------------- | ------------------------------------ |
  | `x402-mina-channel***` | a `ChannelConfig`, giving `channelId` |
  | `x402-mina-voucher***` | a `Voucher`                          |
  | `x402-mina-claim*****` | a `Claim` authorization              |
  | `x402-mina-refund****` | a `Refund` authorization             |

  Distinct tags do the job EVM's distinct EIP-712 type hashes do: a signature over one kind of
  message never verifies as another.

- **A public key is two fields**, `[x, isOdd]`, with `isOdd` as `0` or `1`. In JSON it is the
  base58check `B62…` address.
- **An amount is one field**, the `UInt64` value itself. It is hashed as `UInt64.toFields`, never
  bit-packed with its neighbours.

### Signatures

Every signature in this binding is a Mina Schnorr signature over Pallas, over a **one-field
message** (the tagged digest), made as o1js `Signature.create(privateKey, [digest])` and checked
as `Signature.verify(publicKey, [digest])`:

- The signature prefix is `CodaSignature*******`, on **every** network. This is the domain o1js
  uses in-circuit, so it is the only one a zkApp can verify.
- The nonce is derived deterministically in o1js's *chunked* mode with network id `0x00`. A given
  key and message therefore always give the same `(r, s)`.
- In JSON a signature is o1js `Signature.toBase58()`.

### Amounts and units

The asset is native MINA (token id `1`). Amounts are **nanomina** (10⁻⁹ MINA) as unsigned 64-bit
integers, written as decimal strings in JSON. A value above `2⁶⁴ − 1` is invalid everywhere.

### Time

- A **slot** is Mina's global slot since genesis. Every stored time is a slot.
- The zkApp reads time **only** through `this.currentSlot.requireBetween(lo, hi)`, which the chain
  checks against the slot of the block that includes the command. It never uses a `network.*`
  precondition: `network.timestamp` is derived from constants baked in at compile time and is
  wrong on mainnet after the Mesa fork, and every `network.*` precondition is checked against the
  parent block rather than the including one.
- It never requires an **exact** slot. Every time check is a range.
- `withdrawDelay` is in **seconds**, as on EVM and SVM. The zkApp converts it once:
  `delaySlots = ceil(withdrawDelay / SLOT_SECONDS)`. `SLOT_SECONDS` is a constant of the
  verification key, `90` since the Mesa fork. A fork that changes slot length changes the
  constant with the VK (see [Hard forks](#hard-forks-and-the-verification-key)).
- `hi` in any `requireBetween` MUST NOT exceed the command's own `validUntil`.

### Networks

| Network      | CAIP-2         | `networkId` (in hashes) |
| ------------ | -------------- | ----------------------- |
| Mina mainnet | `mina:mainnet` | `1`                     |
| Mina devnet  | `mina:devnet`  | `0`                     |

`networkId` is a small constant fixed by this binding, the same values Mina's own signer uses for
its network ids. It is **not** Mina's `chainId`, which is a hash over the genesis state and
changes at every hard fork; a channel id bound to it would stop verifying after the next fork.

---

## Channel Lifecycle

### The zkApp

One zkApp account per network holds every MINA channel. Its on-chain state is:

| State             | Meaning                                                                  |
| ----------------- | ------------------------------------------------------------------------ |
| `root`            | root of the channel map, as of the last `reduce`                         |
| `actionCursor`    | the action state up to which `root` is reduced                           |
| `networkId`       | this deployment's `networkId`, set at deploy and never rewritten         |
| `resumedAt`       | the slot at which the current verification key was installed (see below) |

The **channel map** is an indexed Merkle map. Its keys are `channelId`s and receiver addresses.
A channel's value is the Poseidon hash of its **leaf**:

| Leaf field          | Type     | Meaning                                                      |
| ------------------- | -------- | ------------------------------------------------------------ |
| `balance`           | `UInt64` | deposited, less withdrawals and refunds (EVM's meaning)       |
| `totalClaimed`      | `UInt64` | cumulative amount claimed by the receiver                    |
| `withdrawInitiatedAt` | `UInt32` | slot at which a timed withdrawal was initiated, or `0`       |
| `withdrawAmount`    | `UInt64` | amount of the pending timed withdrawal, or `0`               |
| `refundNonce`       | `UInt32` | next nonce a signed refund must carry                         |

A receiver address's value is its **credit**: claimed and refunded MINA reduced but not yet
collected. The map height, the leaf hash's exact layout and the key derivation for a receiver's
credit are fixed by the reference implementation and listed in its vectors.

As on EVM, the unclaimed escrow is `balance − totalClaimed`, and the snapshot fields a verifier
returns mean what they mean on EVM.

### Channel identity

```text
ChannelConfig {
  payer:              PublicKey  // client wallet; signs deposits and withdrawals
  payerAuthorizer:    PublicKey  // signs vouchers; MAY equal payer
  receiver:           PublicKey  // server's payment destination
  receiverAuthorizer: PublicKey  // signs claims and refunds; MAY equal receiver
  tokenId:            Field      // MUST be 1 (native MINA) for this zkApp
  withdrawDelay:      UInt32     // seconds, 900 – 2,592,000
  salt:               Field      // differentiates channels with identical parameters
}

channelId = hashWithPrefix("x402-mina-channel***", [
  payer.x, payer.isOdd,
  payerAuthorizer.x, payerAuthorizer.isOdd,
  receiver.x, receiver.isOdd,
  receiverAuthorizer.x, receiverAuthorizer.isOdd,
  tokenId,
  withdrawDelay,
  salt,
  zkappAddress.x, zkappAddress.isOdd,
  networkId,
])
```

The 14-field preimage binds the config to one zkApp on one network, so the same config gives a
different `channelId` on another deployment or network. `salt` is one field, not 32 bytes: an
arbitrary 32-byte value does not always fit in a Pallas field. In JSON, `channelId` and `salt` are
decimal field strings, as o1js `Field.toString()` prints them.

A **token channel** (a Mina custom token) is not a parameter of this zkApp. A custom token's owner
must approve every transfer and can install its own verification key at a fork, so a token
channel is a separate zkApp with its own verification key. `tokenId` stays in the config so that
binding can share this channel-id derivation.

### Channel creation and deposits

A channel is created implicitly by its first deposit. `deposit(config, amount)`:

- recomputes `channelId` from `config`, and requires `tokenId == 1`, `900 ≤ withdrawDelay ≤
  2,592,000`, `receiverAuthorizer` and `payerAuthorizer` non-zero and `amount > 0`;
- is authorized by a **signed child account update from `payer`** that sends `amount` MINA to the
  zkApp. That update MUST set `incrementNonce`, which is its replay protection, and MUST NOT use
  the full transaction commitment, so that another party may be the fee payer;
- dispatches a `Deposit(channelId, amount)` action. The zkApp's account balance rises at once.

**Anyone may prove and submit a deposit**, and anyone may pay its fee. A deposit is always
applied by `reduce`: it credits the channel, creating the leaf if needed. Top-ups are further
deposits into the same channel.

### Requests and vouchers

```text
Voucher { channelId: Field, maxClaimableAmount: UInt64 }

voucherDigest = hashWithPrefix("x402-mina-voucher***", [channelId, maxClaimableAmount])
signature     = Schnorr(payerAuthorizer, [voucherDigest])
```

The voucher is a **ceiling**, exactly as on EVM: the server may claim any `totalClaimed` up to
`maxClaimableAmount`. Vouchers carry no nonce and no expiry. A later voucher with a higher ceiling
supersedes every earlier one.

The server tracks `chargedCumulativeAmount` per channel. For each request after the first, the
client sets `maxClaimableAmount` to `chargedCumulativeAmount + amount`, where `amount` is the
per-request maximum from the 402.

### Claim and settle

```text
Claim { channelId: Field, totalClaimed: UInt64 }
claimDigest = hashWithPrefix("x402-mina-claim*****", [channelId, totalClaimed])
```

`claim(config, voucher, voucherSignature, totalClaimed, claimSignature)`:

- verifies `voucherSignature` against `payerAuthorizer`, and `claimSignature` (over
  `claimDigest`) against `receiverAuthorizer`, both in-circuit;
- requires `totalClaimed ≤ voucher.maxClaimableAmount`;
- dispatches a `Claim(channelId, totalClaimed)` action. It sends nothing.

`reduce` applies a `Claim` only if `leaf.totalClaimed < totalClaimed ≤ leaf.balance`. It then
adds `Δ = totalClaimed − leaf.totalClaimed` to the receiver's credit and sets `leaf.totalClaimed =
totalClaimed`. Otherwise the action is a no-op.

**Why claim and settle are one operation.** On EVM, `settle(receiver, token)` sweeps one
accumulator per receiver that every claim writes. On Mina a value that every claim writes
serializes every claim through one state precondition, and a split costs two proofs and two
commands per landing instead of one. So a claim credits the receiver directly.

**The claim signature is the receiver side's consent.** A voucher is a ceiling, so landing it in
full could overcharge a payer the server charged less. `claimSignature` binds the amount the
receiver chose. It is relay-friendly: anyone may prove and submit a claim carrying it, including
the receiver itself. A used claim signature is harmless: its `totalClaimed` is no longer above the
channel's, so it reduces to a no-op.

Several channels' claims MAY ride in one command, one proved account update each, up to Mina's
account-update limits.

### Collect

`collect(address)` is proof-authorized and callable by anyone. It debits `address`'s credit in the
map and sends that MINA to `address`. It preconditions on the reducer's `root`, so a collect is
normally **bundled in the same command right after a `reduce`**, proved against the root that
`reduce` produces. If `address` has no account yet, the command must pay Mina's account-creation
fee (`fundNewAccount`), which the network burns.

Payouts are pulled, not pushed, so that no recipient can block anyone else's reduction: a pushed
payout to an account that refuses to receive would make every reduce that pays it fail.

### Reduce

`reduce` is proof-authorized and callable by anyone. It folds the actions after `actionCursor`,
in order and up to a fixed batch size, into the map, and sets the new `root` and `actionCursor`.
It is **total**: every action either applies or becomes a recorded no-op, and nothing in an
action's contents can make `reduce` fail. It sends no MINA.

Each time-dependent action carries the **dispatch slot** its method recorded, one bound of the
method's `currentSlot.requireBetween` window, chosen so that the window's slack falls on the payer
(see [Refund and withdrawal](#refund-and-withdrawal)). Time-dependent rules are judged by dispatch
slots and action order, not by the slot at which `reduce` runs. A server that has dispatched an
action reduces it itself if nobody else does; if nobody reduces, payouts are delayed, but no funds
are at risk.

### Refund and withdrawal

**Cooperative refund.**

```text
Refund { channelId: Field, nonce: UInt32, amount: UInt64 }
refundDigest = hashWithPrefix("x402-mina-refund****", [channelId, nonce, amount])
```

`refund(config, nonce, amount, refundSignature)` verifies `refundSignature` against
`receiverAuthorizer` in-circuit and dispatches `Refund(channelId, nonce, amount)`. Anyone may
prove and submit it. `reduce` applies a refund only when `nonce == leaf.refundNonce`: it
increments `refundNonce` **first**, then moves `min(amount, balance − totalClaimed)` out of
`balance` to the payer's credit, and reduces a pending timed withdrawal by the refunded amount
(cancelling it when the refund covers it). A refund with a stale nonce is a no-op. The nonce
exists because a refund amount is a delta, so its signature could otherwise be replayed until the
escrow ran dry.

There is no unsigned `refund` path: the signed path covers it, with the receiver as its own relay.

**Timed withdrawal** (the payer's escape hatch).

- `initiateWithdraw(config, amount)` is authorized by a **signed child account update from
  `payer`** (nonce-incrementing). It takes a window `[lo, hi]`, requires
  `currentSlot.requireBetween(lo, hi)`, and dispatches `InitiateWithdraw(channelId, amount)` with
  dispatch slot `hi`. `reduce` records `withdrawInitiatedAt = hi` and `withdrawAmount = amount`,
  and makes it a no-op if a withdrawal is already pending or `amount > balance − totalClaimed`.
  Recording the window's **upper** bound means the receiver always gets at least the full delay;
  the window's width only affects how likely the command is to land.
- `finalizeWithdraw(config)` is authorized the same way and takes a window `[lo, hi]` the same
  way, but dispatches `FinalizeWithdraw(channelId)` with dispatch slot **`lo`**, the earliest slot
  at which it can have landed. `reduce` applies it only if `lo ≥ withdrawInitiatedAt +
  delaySlots` **and** `lo ≥ resumedAt + delaySlots`, and then moves `min(withdrawAmount, balance −
  totalClaimed)` out of `balance` to the payer's credit and clears the pending withdrawal. An
  early or unmatched finalize is a no-op.

In both cases the slack of the window falls on the payer, never on the receiver.

A payer's withdrawal authorization is a signed account update rather than an in-circuit
signature, because an in-circuit signature over `(channelId, amount)` would have no nonce: anyone
could replay it after a finalize and freeze the channel again.

**Claims race withdrawals by action order.** A claim dispatched before a finalize is reduced
before it, so it lands. The server MUST dispatch its outstanding claims before
`withdrawInitiatedAt + delaySlots`.

### Authorization summary

| Method                                 | Authorized by                                                    | Who may prove and submit |
| -------------------------------------- | ---------------------------------------------------------------- | ------------------------ |
| `deposit`                              | `payer`'s signed child update (nonce-incrementing)               | anyone                   |
| `claim`                                | `payerAuthorizer`'s voucher and `receiverAuthorizer`'s `Claim`, in-circuit | anyone           |
| `refund`                               | `receiverAuthorizer`'s `Refund`, in-circuit                      | anyone                   |
| `initiateWithdraw`, `finalizeWithdraw` | `payer`'s signed child update (nonce-incrementing)               | the payer's command      |
| `reduce`, `collect`                    | the proof alone                                                  | anyone                   |
| `resume`                               | the zkApp account key, only in a post-fork install command       | the key holder           |

### Preconditions

A zkApp proof commits to its preconditions, and a command fails if any of them no longer holds
when it is included. So that independent channels never invalidate each other:

1. Methods other than `reduce` and `collect` precondition on **no** zkApp state. They only
   dispatch actions.
2. The reducer's `root` and `actionCursor` are the only equality preconditions on shared state.
3. Nothing checks the zkApp's MINA balance by equality. Solvency is checked per leaf, in
   `reduce`. A top-up therefore cannot starve a claim.
4. Time preconditions are ranges on `currentSlot`, bounded above by `validUntil` (see
   [Time](#time)).

### Channel reuse and parameter changes

Channels are long-lived, and the config is immutable, as on EVM. After a refund or withdrawal the
payer may top up and reuse the same channel. Changing any config field needs a new channel.

---

## 402 Response (PaymentRequirements)

The client maps `payTo` → `receiver`, `extra.receiverAuthorizer` → `receiverAuthorizer`,
`extra.withdrawDelay` → `withdrawDelay`, and `asset` → `tokenId`. It fills in its own `payer`,
`payerAuthorizer` and `salt`.

```jsonc
{
  "scheme": "batch-settlement",
  "network": "mina:mainnet",
  "amount": "1000000",                                           // nanomina per request, maximum
  "asset": "wSHV2S4qX9jFsLjQo8r1BsMLH2ZRKsZx6EJd1sbozGPieEC4Jf", // native MINA's token id
  "payTo": "B62qServerReceiver...",
  "maxTimeoutSeconds": 3600,
  "extra": {
    "receiverAuthorizer": "B62qReceiverAuthorizer...",
    "withdrawDelay": 86400,
    "zkappAddress": "B62qChannelZkapp...",
    "verificationKeyHash": "1234...decimal field",
    "minDeposit": "10000000000"
  }
}
```

| Field                       | Type     | Required | Description                                                                                         |
| --------------------------- | -------- | -------- | --------------------------------------------------------------------------------------------------- |
| `asset`                     | `string` | yes      | The base58 token id. This binding accepts only native MINA's.                                       |
| `extra.receiverAuthorizer`  | `string` | yes      | `B62…` key that signs claims and refunds                                                            |
| `extra.withdrawDelay`       | `number` | yes      | Seconds, `900` – `2,592,000`, and `≥ maxTimeoutSeconds`                                             |
| `extra.zkappAddress`        | `string` | yes      | The channel zkApp the server uses                                                                    |
| `extra.verificationKeyHash` | `string` | yes      | That zkApp's installed VK hash, decimal                                                             |
| `extra.minDeposit`          | `string` | optional | Atomic deposit target. When present, MUST be a positive integer `>= amount`.                        |
| `extra.voucherManager`      | `string` | optional | `"server"` (default). `"facilitator"` is not defined for Mina in this version.                      |
| `extra.channelState`        | `object` | optional | Corrective 402 only, as on EVM                                                                      |
| `extra.voucherState`        | `object` | optional | Corrective 402 only, as on EVM                                                                      |

**The zkApp is not negotiated.** `extra.zkappAddress` and `extra.verificationKeyHash` are
published so a client can refuse a mismatch, not so a server can choose them. A client MUST hold
its own copy of the deployment for each network (see
[Reference deployment](#reference-deployment)) and MUST refuse a 402 whose pair differs from it.
A facilitator MUST do the same.

`withdrawDelay ≥ maxTimeoutSeconds` is required, as on SVM, so that a request's payment cannot
outlive the payer's ability to exit.

---

## Client: Payment Construction

As on EVM, the payload `type` is `deposit`, `voucher` or `refund`, chosen by channel state.

### Deposit Payload

`deposit.transaction` is a zkApp command, as o1js `Transaction.toJSON()`, that calls `deposit`.
The client MUST have signed the `payer` account update. The command MAY lack the fee payer's
signature and the `deposit` proof, which the server or a facilitator then supplies; the payer's
update does not use the full commitment, so attaching them does not invalidate it. The server
MUST check that the command's `deposit` call carries this `channelConfig` and `deposit.amount`
before it proves or submits anything.

```jsonc
{
  "x402Version": 2,
  "accepted": { "...": "..." },
  "payload": {
    "type": "deposit",
    "channelConfig": {
      "payer": "B62qClient...",
      "payerAuthorizer": "B62qClientVoucherKey...",
      "receiver": "B62qServerReceiver...",
      "receiverAuthorizer": "B62qReceiverAuthorizer...",
      "tokenId": "1",
      "withdrawDelay": 86400,
      "salt": "0"
    },
    "voucher": {
      "channelId": "2165...decimal field",
      "maxClaimableAmount": "1000000",
      "signature": "7mX...base58 Schnorr signature"
    },
    "deposit": {
      "amount": "10000000000",
      "transaction": "{...zkApp command JSON...}"
    }
  }
}
```

### Voucher Payload

```jsonc
{
  "x402Version": 2,
  "accepted": { "...": "..." },
  "payload": {
    "type": "voucher",
    "channelConfig": { "...": "..." },
    "voucher": {
      "channelId": "2165...decimal field",
      "maxClaimableAmount": "5000000",
      "signature": "7mX...base58 Schnorr signature"
    }
  }
}
```

### Refund Payload

As on EVM: a zero-charge voucher (`maxClaimableAmount == chargedCumulativeAmount`) and an
optional `amount`. The server completes it with `refundNonce`, the claim it lands first, and its
`Refund` signature.

---

## Server: State & Forwarding

The server keeps the per-channel state the EVM binding lists, with these differences:

| State field           | On Mina                                                                    |
| --------------------- | -------------------------------------------------------------------------- |
| `withdrawRequestedAt` | the leaf's `withdrawInitiatedAt`, a **slot**                               |
| `refundNonce`         | the leaf's `refundNonce`                                                   |
| `pendingActions`      | actions this server dispatched that are not yet reduced                    |

**Reading the map.** The chain stores only `root` and the action state, not the leaves. A server
or facilitator rebuilds the map by reducing the zkApp's actions, fetched from an archive node, and
MUST check the result against the on-chain `actionCursor` and `root` before trusting it. An
archive is untrusted: one that answers wrongly fails the check, and the reader fails closed.

**Landed and counted.** The leaf as of `root` lags the chain's actions. A server SHOULD treat a
deposit as backing vouchers only once its dispatch is final by its own confirmation policy (Mina's
documentation recommends 15 blocks), and MUST NOT treat it so before the action is included with
an empty `failureReason`. An included command can fail and still be charged its fee.

Request processing, the payment response contract and the cooperative refund flow are as on EVM.
A refund lands as one command: `claim` (if the charge is above `totalClaimed`) then `refund`.

---

## Facilitator Interface

A facilitator is **optional** on Mina. Any party may prove and submit any command another party
has authorized, and any party may pay its fee, so a server MAY do everything below itself. A
facilitator that offers this binding uses the standard `/verify`, `/settle` and `/supported`.

### POST /verify

Verifies a `deposit`, `voucher` or `refund` payload (see
[Verification Rules](#verification-rules)) and returns the channel snapshot from the map, as on
EVM, with `withdrawRequestedAt` as a slot.

### POST /settle

| `payload.type` | Command submitted                                     | Effect                                              |
| -------------- | ----------------------------------------------------- | --------------------------------------------------- |
| `"deposit"`    | the client's `deposit` command, proved and fee-paid   | `Deposit` dispatched; escrow received               |
| `"claim"`      | `claim` for each row, proved                          | `Claim` actions dispatched; nothing sent yet        |
| `"settle"`     | `reduce`, then `collect(receiver)` in the same command | pending actions reduced; the receiver's credit sent |
| `"refund"`     | `claim` (if needed) then `refund`, proved             | `Refund` dispatched                                 |

The server-authored `claim` payload carries, per row, the channel config, the voucher, its
signature, the `totalClaimed` to land, and the `receiverAuthorizer`'s `Claim` signature over it.
Unlike EVM there is no batch-wide authorizer signature: each row is its own `Claim`, signed over
its own `(channelId, totalClaimed)`. The `settle` payload is `{ "type": "settle", "receiver":
"B62q…" }`.

`transaction` in a settle response is the zkApp command's hash. If the command was accepted to the
pool but its inclusion cannot be established, the facilitator MAY return `settlement_pending`
with that hash, as on EVM.

### GET /supported

```jsonc
{
  "kinds": [
    {
      "x402Version": 2,
      "scheme": "batch-settlement",
      "network": "mina:mainnet",
      "extra": {
        "zkappAddress": "B62qChannelZkapp...",
        "verificationKeyHash": "1234...decimal field"
      }
    }
  ],
  "extensions": [],
  "signers": { "mina:*": ["B62qFacilitatorFeePayer..."] }
}
```

A facilitator MAY advertise a `receiverAuthorizer`, as on EVM, to sign claims and refunds for a
server that delegates. A server that delegates refund consent MUST authenticate itself to the
facilitator, as on EVM.

### Verification Rules

A verifier (the server, or a facilitator) MUST enforce:

1. **Deployment match**: `extra.zkappAddress` and `extra.verificationKeyHash` equal the
   verifier's own pinned deployment for `network`, and the chain reports that VK installed on
   that account.
2. **Channel config consistency**: `hashWithPrefix("x402-mina-channel***", …)` over the config,
   the zkApp address and `networkId` equals `voucher.channelId`.
3. **Asset match**: `channelConfig.tokenId` is `1` and `asset` is native MINA's token id.
4. **Receiver match**: `channelConfig.receiver` equals `payTo`.
5. **Receiver authorizer match**: `channelConfig.receiverAuthorizer` equals
   `extra.receiverAuthorizer`.
6. **Withdraw delay match**: `channelConfig.withdrawDelay` equals `extra.withdrawDelay`.
7. **Amount range**: every amount is a decimal integer in `[0, 2⁶⁴ − 1]`.
8. **Signature validity**: the voucher signature verifies against `payerAuthorizer` over
   `voucherDigest`, under [Signatures](#signatures).
9. **Channel existence**: the leaf exists in the verified map with a positive `balance`.
10. **Deposit sufficiency**: `maxClaimableAmount ≤ leaf.balance` (or `≤ leaf.balance +
    deposit.amount` for a deposit payload).
11. **Not below claimed**: for voucher and deposit payloads, `maxClaimableAmount ≥
    leaf.totalClaimed + requirements.amount`, and strictly greater than `leaf.totalClaimed`.
12. **Deposit command**: for a deposit payload, the command calls `deposit` on the pinned zkApp
    with this config and `deposit.amount`, the `payer` update is signed by `payer`, sets
    `incrementNonce`, sends exactly `deposit.amount`, and does not use the full commitment, and
    the payer's balance covers it.
13. **Signed refunds**: the refund nonce equals the leaf's `refundNonce` and the `Refund`
    signature binds the same `amount`.

Every `/verify` response's `extra`, and every `/settle` response's `extra.channelState`, carries
the snapshot (`balance`, `totalClaimed`, `withdrawRequestedAt`, `refundNonce`). If
`withdrawRequestedAt` is non-zero, outstanding vouchers should be claimed promptly.

---

## Claim & Settlement Strategy

The EVM strategies (periodic, threshold, on withdrawal) apply unchanged. On Mina:

- A server lands a voucher with `claim`, then `reduce` and `collect` once the claim is included.
  If another party reduces first, the server only needs to `collect`.
- **Outstanding claims MUST be dispatched before `withdrawInitiatedAt + delaySlots`.** A claim
  dispatched after a finalize is reduced after it and finds the escrow gone.
- A server SHOULD skip a `collect` whose credit is below the command's fee.

---

## Client Verification Rules

As on EVM: `PAYMENT-RESPONSE` `extra` is untrusted, the client updates its local state only from
`extra.chargedAmount`, and recovers through a corrective 402.

**Recovery after state loss.** Channel identity is deterministic. The client recomputes
`channelId` from the 402 plus its own `payer`, `payerAuthorizer` and `salt`, and reads the leaf
from the map, rebuilt and checked against the chain as in
[Server: State & Forwarding](#server-state--forwarding). The baseline rules are EVM's.

---

## Hard forks and the verification key

A Mina hard fork changes the proof system, so every zkApp's verification key goes stale. From
the fork's stop slot until a new VK is installed, no proof-authorized method on the zkApp can run,
and channel funds are frozen. After a protocol-version change, Mina lets only the account's own
key change the VK (`setVerificationKey` and `access` fall back to `signature`). This binding
requires:

- **Permissions.** `access: proof`; `setVerificationKey: impossibleDuringCurrentVersion`;
  `editState`, `send` and `editActionState`: `proof`; every other permission `impossible`. The
  account key can therefore act **only** after a fork, and then only to install a VK. Without
  `access: proof`, anyone could close the post-fork window with an empty update.
- **One install, with `resume`.** The installer sends the signed VK update and a call to
  `resume()` in **one command**. `resume` records `resumedAt` as the current slot.
  `finalizeWithdraw` additionally requires `resumedAt + delaySlots`, so the receiver always gets
  a full delay after the thaw to land its claims.
- **Formats are frozen across forks.** The action encoding, the leaf and its hash, the receiver
  credit key and the map height MUST NOT change at a VK install: every post-fork VK must reduce
  pre-fork actions and read the pre-fork map. Changing any of them is a new zkApp and a drain.
- **Before the stop slot**, a server SHOULD land every voucher it holds.
- **Publishing the post-fork VK.** The deployment publishes the post-fork VK, built reproducibly
  from tagged source with its source diff, before the stop slot. Clients and verifiers pin each
  `(verificationKeyHash, txnVersion)` pair per network and refuse any other. The hash alone is
  not enough: the pre-fork VK stays installed until the install.

---

## Error Codes

The error codes are the EVM binding's with `evm` replaced by `mina`, less those specific to
ERC-3009, Permit2, EIP-2612, ERC-20 approvals and the EIP-712 token domain, plus:

| Error Code                                              | Description                                                                                      |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `invalid_batch_settlement_mina_zkapp_mismatch`          | `extra.zkappAddress` or `extra.verificationKeyHash` differs from the pinned deployment            |
| `invalid_batch_settlement_mina_vk_not_installed`        | The chain reports a different VK on the zkApp account (for example, after a fork, before install) |
| `invalid_batch_settlement_mina_amount_out_of_range`     | An amount is above `2⁶⁴ − 1`                                                                     |
| `invalid_batch_settlement_mina_withdraw_delay_below_timeout` | `withdrawDelay < maxTimeoutSeconds`                                                         |
| `invalid_batch_settlement_mina_deposit_command`         | The deposit command does not match the payload (zkApp, method, config, amount, payer update)       |
| `invalid_batch_settlement_mina_map_unverified`          | The rebuilt channel map does not match the on-chain root and action state                          |
| `invalid_batch_settlement_mina_proof_failed`            | Proving a command failed                                                                          |
| `invalid_batch_settlement_mina_precondition_failed`     | The command was included with a non-empty `failureReason`                                         |

---

## Security and Trust

1. **Capital risk and replay.** As on EVM: the client risks up to its signed ceiling, the
   receiver authorizer chooses the claimed total within it, and cumulative totals make voucher
   nonces unnecessary. A replayed `Claim` signature reduces to a no-op. Signed refunds carry a
   per-channel nonce. Deposit and withdrawal updates carry the payer account's own nonce.
2. **Authorization scope.** Distinct 20-byte tags keep vouchers, claims, refunds and channel ids
   apart. Every signature uses `CodaSignature*******` on every network, which is also the domain
   of devnet transaction signatures; a voucher's message is a tagged Poseidon digest, so turning
   one into a transaction signature is a preimage problem. Implementations SHOULD still use a
   voucher key that signs no transactions. `networkId` and `zkappAddress` in `channelId` keep a
   voucher from verifying on another network or deployment.
3. **Settlement atomicity.** Each method is one proved account update in one command, and either
   the whole command applies or none of it does, though a failed command is still charged its
   fee. `reduce` is total, so no action can block the queue. Payouts are pulled, so no recipient
   can block a reduction.
4. **Withdrawal delay.** The 15 min – 30 day bounds and the escape hatch are EVM's. The delay is
   counted in slots of the VK's `SLOT_SECONDS`. A server that publishes a short delay is betting
   that its claim lands inside it: 900 s is 10 slots, and Mina carries a limited number of zkApp
   commands per block.
5. **Liveness.** If nobody reduces, claims and withdrawals are delayed, not lost. Anyone may
   reduce. A server SHOULD reduce its own pending actions.
6. **The upgrade key.** After a hard fork, the holder of the zkApp account key can install any
   verification key, including one that pays the escrow to itself. Funds are frozen until the
   install, and a wrong install lasts until the next fork. Nothing on chain binds the holder to a
   faithful port; the off-chain commitment is the reproducible, published VK and the pinned
   `(verificationKeyHash, txnVersion)`. A deployment SHOULD hold this key as a threshold key.

---

## Reference deployment

| Network        | `zkappAddress` | `verificationKeyHash` | `txnVersion` |
| -------------- | -------------- | --------------------- | ------------ |
| `mina:devnet`  | TBD            | TBD                   | TBD          |
| `mina:mainnet` | TBD            | TBD                   | TBD          |

The reference zkApp is written in o1js and is also proved by a Rust prover; both are checked
against the same vectors.

---

## Version History

| Version | Date       | Changes       | Authors |
| ------- | ---------- | ------------- | ------- |
| v0.1    | 2026-10-28 | Initial draft | TOON    |
