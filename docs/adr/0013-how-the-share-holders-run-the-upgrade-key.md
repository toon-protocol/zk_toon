---
status: accepted
---

# How the share holders run the upgrade key

The upgrade key is a 2-of-3 FROST key (ADR 0012), and it is the vault account's own key, whose permissions can never
change (ADR 0006). So it can never be rotated. The only remedies for a lost or leaked key share are a re-share (#105):
a refresh, or replacing a holder. Both need two working shares. If two shares are lost, nobody can install the next
fork's verification key, and the vault stays frozen after that fork's stop slot. If two leak, whoever holds them can
install a key that drains the vault after the next fork. This ADR decides the tooling, how shares are stored, backed
up and destroyed, how the holders show they still have their shares, and how a holder is replaced (#122).

The procedures are in `docs/upgrade-key-holders.md`, and the holders' record in `docs/upgrade-key-record.md`.

## Decision

- **One key, and one ceremony, per vault.** The vault's address is the upgrade key's public key, so every vault has its
  own distributed key generation (DKG), run before the vault is registered. Its result is the vault's address, which
  is what `register(vault, …)` takes (ADR 0011) and what the vault's fork notice is published for. Each vault's
  address, its holders and its check log are kept in `docs/upgrade-key-record.md`.
- **The tooling is our own thin CLI, `zk-toon-upgrade-key`,** in this repo, over the crate from #104 and #105, so the
  audited `frost-bluepallas` is the only cryptography in it. Its commands: `init` (a holder's communication key pair),
  `dkg`, `sign`, `check`, `refresh`, `repair` and `verify-share`. It writes key shares only encrypted.
- **Messages travel as encrypted files.** Every DKG, signing-round and re-share message is signed with its sender's
  communication key and encrypted to its recipients' keys, then carried by any channel (email, chat, a USB stick). The
  CLI refuses a message not signed by a holder of that vault. Holders exchange communication keys at setup and check
  their fingerprints face to face or on a video call. The fingerprints go in the holders' record.
- **The DKG's first round is checked as a broadcast.** Before the second round, each holder reads out a hash of all three
  first-round packages (`dkg` prints it) over a second channel. If any two hashes differ, the DKG is
  abandoned and run again.
- **A holder never signs a commitment it didn't compute.** The signer sees only a field element (ADR 0012), so before
  signing each holder computes the full commitment again from the transaction's parameters with the transaction
  builder's prepare operation (#123), on a networked machine, and refuses if it differs. Before signing a key install,
  each holder also rebuilds the key from the fork notice's source tag and refuses unless it matches. Without this
  check, two holders could install a key that drains the vault.
- **Storage:** the share lives in a file encrypted with a passphrase (age, scrypt), on a device that stays offline
  while it holds the share. It never sits in plaintext on a networked machine, or in any cloud storage or synced
  folder, even encrypted.
- **Backups:** each holder keeps exactly one backup: an encrypted copy on separate media, in a separate building. The
  passphrase is written down and kept apart from both copies. A holder who loses the passphrase has lost the share.
  Each share generation (the shares from one DKG or one re-share) gets its own backup media, so the media can be
  destroyed along with the generation.
- **Old shares are destroyed after every re-share,** once every pair of new shares has passed a check. Each holder
  deletes the old working copy, physically destroys the old backup media, and signs a destruction statement with its
  communication key, which goes in the holders' record. A refresh protects the key only if this happens: two old
  shares still sign together. Destruction can be attested, not proven. The round-message files are deleted from every
  channel that carried them, and a leaked communication key counts as a suspected leak of that holder's share. A share
  made by a repair is an old share once the refresh after it is done.
- **Pre-fork check:** each holder runs `verify-share` on both copies, which checks the share against the vault's
  public key package. Then each of the three pairs threshold-signs a check value, and anyone can verify the signatures
  against the vault's address. The check value is a Poseidon hash of a domain tag, the vault's address, the date and
  a fresh random contribution from each holder. The CLI derives it itself, so no holder can pass off a real
  transaction's commitment as a check. The holders sign it under the network ID the vault isn't on. A check runs
  within 7 days of a fork's stop slot being announced and at least 42 days before that stop slot, which leaves 28
  days to replace a holder before the fork notice is due. A fork announced with less notice gets a check at once. It
  also runs after the ceremony, after every re-share and every 6 months, so a lost share isn't discovered only at
  the next fork. The check log keeps the date, the contributions, the check value and the three signatures, so anyone
  can verify it.
- **Replacing a holder:** a holder is replaced after a suspected leak of its share, a share lost with no working
  backup, a failed check, or the holder leaving their role. The two remaining holders decide, and the leaving holder's
  agreement isn't needed. The procedure is #105's: the two remaining holders repair the leaving holder's identifier
  for the new holder, then all three refresh. Old shares are destroyed as above, and the change is published at the
  vault's zkApp URI and recorded in the holders' record. The new holder must still fit ADR 0012's roles.
- **Two shares lost or leaked** can't be repaired. The operator announces it at the vault's zkApp URI at once. Payers
  should leave before the next fork's stop slot, and a new vault is deployed.

## Rejected

- **Raspberry-Devs' `mina-frost-client`.** It is outside the Veridise audit, keeps key shares in cleartext in its
  config file, and has no refresh or repair, so re-sharing would need our own tool anyway.
- **ZcashFoundation's `frostd` server** for messages. Someone would have to run it, and the share device would have to
  be online for a whole session. Signing is rare (delegations and one install per fork), so files are enough, and they
  work with an offline device.
- **A hardware-backed share.** Stronger, but it needs custom tooling for each device. An encrypted file kept offline
  gives the same protection against remote theft.
- **More than one backup per holder.** Every copy is something else to destroy after a re-share. With three holders,
  one holder losing both copies still leaves two working shares and a replacement.
- **A check that signs a value one holder picks.** That holder could pick a real transaction's commitment.

## Not yet done

- The CLI isn't built (#125). It needs #104 and #105.
- Registration needs the vault's key to sign the vault's first account update (ADR 0011). That signature doesn't go
  through the threshold signer yet (#126): #123 covers only delegation and the key install.
- The independent holder hasn't been agreed, and no ceremony has been run, so the holders' record names no vault yet.
