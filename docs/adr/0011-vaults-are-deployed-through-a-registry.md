---
status: accepted
---

# Vaults are deployed through a registry, and the check refuses any other

Issue #79 holds the trial and the problem; #80 built this. (The issue calls this ADR 0009, but 0009 was taken by the
subsidy-reporting decision, so this is 0011.)

A vault deployed under its own key can have anything written to it before its account is locked: `init` and `deploy`
run under that key's signature and aren't in the circuit (ADR 0008). A deployer can sign in a fake deposit and a fake
close of it with an invented nullifier. The history replays cleanly and the books balance, so the vault check passes
it. The phantom note's real nullifier is still unspent, so once a payer deposits, the deployer closes the note for real
and takes the deposit. A close doesn't name its note (ADR 0005), so replay can't catch it. ADR 0008 could vouch only
for a vault first seen locked with nothing dispatched.

## Decision

A **vault registry** zkApp deploys each vault in one transaction (`o1js/src/vault-registry.ts`). `register(vault, vk,
slot, uri)` is proved, and its proof requires that:

- the account at `vault` is new (`isNew`, a precondition on the child update);
- the key's hash is the vault code hash, which is fixed in the registry's circuit;
- the permissions are ADR 0006's table (`lockedPermissions` in `vault.ts`, which `deploy` uses too);
- the app state is what `init` writes for a vault created at `slot` (`VaultState.initial`, which `init` uses too), and
  the transaction lands in `slot` or the next, so `creationTime` is the registration slot;
- the zkApp URI is the one given: its hash is part of the update, and any URI is accepted.

It then records the vault's address as a registry action: the entry is the address and nothing else. The vault's
`@method`s and key don't change: the code hash from `npm run keys` is the same as a build of the base commit
(`18683408031881884777656720181449885515444520266556316685557148949849565333999`, both).

The account never has an unlocked phase, so no fake history can be written to it. The child update is signed by the
vault's key (as any new account's first update is) and the registry's proof constrains everything that signature
covers. Writes later in the same transaction are refused by the permissions, and writes earlier fail `isNew`.

The vault check requires the rule and has no option to turn it off:

- **`registry`**: the vault's address is among the entries of the pinned registry. Entries come from an archive and
  count only if they hash up to the registry's on-chain action state (`registry.actionState`).
- **The registry is judged too**: its verification key hash against the published one (`registry.codeHash`), its
  permissions against ADR 0006's table (`registry.permissions.*`), and no vesting schedule.
- Every other rule of ADR 0008 stays, and so does the replay. A registered vault is still replayed.

The check takes one registry address and one code hash for each of the registry and the vault. Tests of the older
rules show a forged vault as listed, so they see only their own refusal; `vault-check.json` has cases for a listed
vault, an unlisted one and a wrong registry.

The published keys gain the registry's key and code hash (`keys.registry`). A registry's address isn't a build output,
so it isn't there: `o1js/registry-deployments.json` holds one record per network: the registry's address, and the slot
and action state when it was seen empty and locked, which anyone can reproduce from an archive. It holds no record
yet. A deployer could fake entries before locking the registry, so a wallet takes the registry from a record it can
reproduce. Deploying one on devnet and lightnet, and the first record, are #81.

## Hard forks

A fork ends registered status. The registry fixes the vault code hash, and a fork brings a new vault key, hence a new
registry and a new pin. A vault from before the fork isn't registered by the new registry, so it is refused for new
deposits, while deposits already in it can still leave through the methods and the fork notice (ADR 0006). Nothing
re-registers an old vault. The registry has no fork notice and needs none: it is replaced, not upgraded.

**The registry's key is discarded** (#81). A registry is deployed under a random key that lives only in the deploying
process (`npm run registry -- deploy`). Its `setVerificationKey` permission falls back to `signature` after a fork,
so a kept key is the only way its code could ever change; with none, an old registry can't be given new code after a
fork, which closes the first limit below for a registry deployed this way. Nothing is lost: `send` is `proof`, the
account holds nothing, and only `setDelegate` needs a signature.

**Limits:**

- **A wallet that still pins an old registry after a fork can pass a vault forged after it,** unless the registry's
  key was discarded, as the devnet one will be. The old registry's permissions let its key be replaced after the
  fork, and a vault forged under a new-version key is not one the old registry deployed, but the check looks only at
  the old registry's entries and the old key hash.
- **A wallet must update its pin before a fork** (to the new registry and code hash, which each fork publishes).
- A registry's deployer could list entries before locking it. The deployment record covers that.
- A URI isn't judged: a pass doesn't show it is real or watched.
- **The key's data isn't compared, only its hash, and on a node that is not safe** (#81). `{ data: <rogue>, hash:
  <published> }` on a new account is accepted by `LocalBlockchain` and by a single-node lightnet. On a fresh lightnet
  the account then runs the rogue contract: its proofs are accepted, the published contract's are refused, and the
  vault check passes the account. After an honest vault had registered on the same chain, the reverse held. Mina's
  binary form recomputes a key's hash from its data, so peers that get the command by gossip should refuse it, but
  that hasn't run on devnet (`o1js/lightnet/README.md`). This reopens the decision that the check stays hash-only;
  until it is settled, no registry is deployed on devnet and no sighting is published.
- Registration is permissionless and costs only the transaction, so an operator can add entries cheaply and a long
  list reads slowly.

**Spotting a fork from the account's transaction version.** The `setVerificationKey` permission carries the
transaction version the account was deployed under, and the check already compares it with this build's
(`permissions.setVerificationKey`). So a wallet whose build has moved to a new version refuses a vault and a registry
from before it. But a wallet on the old build sees equal versions, and the account holds nothing of the network's
current version, so the version can't tell a stale pin that a fork happened. LocalBlockchain can't raise it, so this is
from reading the permission and o1js's source, not from a fork.

## Rejected

- **A Merkle root of entries.** It needs someone to keep the tree and carry witnesses, makes registration permissioned
  or the root contested, and the action state already commits to every entry. Entries are actions.
- **Accepting old entries across a fork.** The old registry's key could be replaced after the fork, and a fork exists
  to change the vault's key, so an old entry vouches for a key the new code isn't.
- **Re-attesting an old vault.** Whoever re-attests vouches for a history the registry never saw. Nothing re-registers.
- **Attestations as the trust root.** A signature vouching for a vault makes the signer the party to trust. The
  registry's proof makes the rule a property of the chain.
- **An `@method` initialiser,** which ADR 0008 rejected.
- **An option to turn the rule off, or trusting a sighting at `dispatched: 0`.** `smoke-1` and `short-1` are
  refused. A short-window devnet vault is still deployed directly, and the check refuses it.

## What the tests show

`vault-registry-attacks.test.ts`, on a chain that checks proofs and in the proofs-on set (`proofs-on.ts`), asserts
the reason for each rejection: an address that already has an account, a write to the vault earlier in the same
transaction (both `Account_is_new_precondition_unsatisfied`), a later write of state, actions or permissions
(`Update_not_permitted_*`), a vault change after proving, another key (`not the published vault`, when the
transaction is built), an entry added without a proof, a rogue key pair, and two URIs under one compiled key.
`vault-registry.test.ts` compares `register`'s result with a direct deploy's, field by field.
