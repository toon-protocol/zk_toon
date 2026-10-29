---
status: accepted
---

# The vault's account permissions

The vault holds every deposit, and the account's permissions decide who can touch it (#51). The upgrade
key, the vault account's own key, must not be able to move funds, rewrite state or stop an escape. Mina
gives no way to leave it out, so the permissions fence it in.

## The permissions

| Permission | Value | Why |
|---|---|---|
| `setVerificationKey` | `impossibleDuringCurrentVersion` | Replaceable only after a hard fork, by the upgrade key |
| `setPermissions`, `setTiming` | `impossible` | Nothing may loosen the rest or lock funds with a vesting schedule |
| `editState`, `send`, `editActionState` | `proof` | Only the vault's own methods change state, pay out or touch actions |
| `access` | `none` | Unchanged. `proof` would refuse the upgrade key's delegation too, and a signed update with no change does nothing |
| `incrementNonce`, `setZkappUri`, `setVotingFor`, `setTokenSymbol` | `impossible` | Nothing needs them. The URI is set once, at deploy |
| `setDelegate` | `signature` | Deliberate: the operator may stake the vault's balance with a block producer. Delegating can't move funds |
| `receive` | `none` | Unchanged. Anyone may credit the vault |

`access` stays `none` because two things conflict. The first design had `access: proof`, so that every update to the
vault's account runs one of its own methods. It also lets the operator to be able to stake the vault's
balance, and a delegation is an update authorised by the upgrade key's signature. `access` gates every update
to the account, whatever field it changes, so `proof` would refuse the delegation. Delegation is kept; the
fields an update could change are what is fenced, and an update that changes none of them can do nothing.
An empty signed update is therefore accepted, and no test refuses it.

`deposit` credits the vault with `payer.send({ to: this, … })`, so the MINA lands on the deposit method's
own account update and carries its proof, rather than on a separate update to the vault's account. This isn't
needed under `access: none`, but it keeps the deposit working if `access` is ever tightened.

A signed update by the upgrade key increments the vault account's nonce unless it uses the full commitment,
and `incrementNonce` is `impossible`. So a delegation must be authorised with the full commitment, with no
nonce increment (replay protection comes from the fee payer's nonce).

## After a hard fork

`impossibleDuringCurrentVersion` is a verification-key permission. o1js documents it as `impossible`
while the account's transaction version is the current protocol version, and as `signature` once a hard
fork raises the version
(`Permissions.VerificationKey.impossibleDuringCurrentVersion`, with `impossibleDuringCurrentVersion` in
o1js's `Permissions` docs). That is deliberate: a fork changes the proof system, every verification key goes
stale, and without a way to replace it the vault would freeze every deposit.

So after a fork the upgrade key can install any verification key, including one that drains the vault.
The vault can't stop that. The fork notice limits the damage.

## The fork notice

The zkApp URI is set once at deploy and names the vault's fixed announcement location. At least 14 days
before a fork's stop slot, the operator publishes the post-fork verification key there, with its source
tag and a reproducible build, so anyone can rebuild it and compare.

A payer who starts an escape when the notice goes up can then finalize before the stop slot. The 14 days
are a 2-day challenge window, a reduce, and slack for congestion and for payers who check weekly.

Finalize needs a proof. An escape that isn't finalized is stuck at the stop slot until the new key is
installed.

The notice is a promise made off chain. The vault doesn't enforce it.

## The upgrade key

It should be held as a threshold key: threshold Schnorr over Pallas, since Mina has no native multisig.
Tooling for it, and the page at the URI, aren't built here.

## What a payer is guaranteed

While the protocol version stays the same, nobody can change the verification key, the permissions, the
timing, the state, the nonce, the URI or the balance except through the vault's own methods, and no owner action stops or
delays an escape. The upgrade key's only reach is delegation. Across a hard fork, the guarantee is the
fork notice: a payer who watches the URI can leave before the stop slot. A payer who doesn't watch it
trusts the key holders.

## Rejected

- **Destroying the key.** The first incompatible fork would freeze every deposit for good.
- **A key with no notice.** Payers would have to trust the key holders across every fork.

Behaviour after a fork isn't tested: LocalBlockchain can't raise the transaction version.
