---
status: accepted
---

# The upgrade key is a 2-of-3 FROST key

The upgrade key delegates the vault's balance and, after a hard fork, installs the vault's new verification key
(ADR 0006). Whoever holds it can install a key that drains the vault, so no single party may hold it. Mina has no
native multisig, so it is a threshold Schnorr key over Pallas: three key shares, any two of which sign (#104).

## Decision

- **Three share holders:** the operator, the TOON team and one independent holder (an auditor, a known community
  member or a block producer). Not the Mina team: they ship the forks, and declined for that reason.
- **The key is made by distributed key generation** (FROST's Pedersen DKG with proofs of knowledge), so nobody ever
  holds the whole key. A trusted dealer is used only in tests.
- **Signing is FROST's two rounds, adapted to Mina's Schnorr:** Mina's Poseidon challenge with the network's domain
  string, and every signer negates its nonce when the combined R has an odd y. Nonces are random and used once,
  never Mina's deterministic ones.
- **The signer signs one field element, a transaction's full commitment, under a stated network ID.** It never sees the
  transaction; the transaction builder computes the commitment and attaches the signature.
- **The implementation is `frost-bluepallas`** from Raspberry-Devs/mina-multi-sig, on ZcashFoundation's `frost-core`,
  pinned by git commit (`e9b5ffc`) and wrapped by a thin crate here. Veridise audited it at `1457cdd` (June 2026); the
  pinned commit adds that audit's fixes. Our tests check its signatures against this repo's pinned `mina-signer`
  under both network IDs.

## Rejected

- **Our own `frost-core` ciphersuite, or hand-rolled FROST.** More cryptographic code to review, and no audit.
  `frost-bluepallas` is the same design, built for the same reason: verification-key updates after a fork.
- **A trusted dealer for the real key.** The dealer holds the whole key once, which defeats three holders.
- **The Mina team as a share holder.** The party that ships a fork shouldn't also be able to install the key after it.
- **Mina's deterministic nonces.** A threshold signer can't derive them without the whole key, and a reused nonce
  leaks the key.

Tooling for the share holders (running the DKG, exchanging round messages, storing a key share) isn't decided here.
