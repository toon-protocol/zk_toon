# The upgrade key's share holders

What each share holder does. ADR 0012 covers what the upgrade key is, and ADR 0013 covers why it is run this way.
The record of who holds each vault's key shares, with its check log, is `docs/upgrade-key-record.md`.

The `zk-toon-upgrade-key` CLI named here isn't built yet (it needs #104 and #105). These steps say what it must
let a holder do.

## Setting up as a holder

1. Get a device for the share that can stay offline: no network while it holds the share. Each share generation's
   backup goes on new removable media.
2. Run `zk-toon-upgrade-key init` on that device. It makes your communication key pair, which signs and encrypts
   your messages. It is not your key share.
3. Send your public communication key to the other two holders. Read its fingerprint aloud face to face or on a video
   call, and check theirs. Add all three fingerprints to the holders' record.

## The ceremony (one per vault)

Run it before the vault is registered. All three holders take part.

1. One holder starts `zk-toon-upgrade-key dkg` with the threshold (2), the three holders and the network. Each
   holder's first-round package goes to the other two as an encrypted file.
2. **Check the broadcast.** Once you have both other packages, `dkg` prints a hash of all three. Read it to the
   other holders over a second channel, not the one that carried the files. If any hash differs, stop and start
   again.
3. Run the second round. Each holder ends with its key share, encrypted under its passphrase, and the vault's public
   key package. Every holder's CLI prints the vault's address. The three addresses must match.
4. Make your backup (below), then run the first pre-fork check (below) with all three pairs.
5. Delete every round-message file from the channels that carried it. Add the vault's address and the date to the
   holders' record. The vault is registered at that address, and its fork
   notice is published for it.

## Making a backup

Make one each time you get a new share generation: after the ceremony, a refresh or a replacement.

1. Copy the encrypted share file to this generation's backup media. Never decrypt it on a networked machine.
2. Run `zk-toon-upgrade-key verify-share` on the copy. It decrypts the copy and checks it against the vault's public
   key package.
3. Label the media with the vault's address and the generation number, and take it to a building other than the one
   your device is in.
4. Write your passphrase down and keep it somewhere apart from both copies. Anyone who finds a copy and the passphrase
   together has your share. If you lose the passphrase, you have lost the share.

Keep exactly one backup. Don't put the share, even encrypted, in cloud storage, a synced folder or a password
manager.

## Signing a transaction

The upgrade key signs a vault's registration, a delegation, and after a fork, the install of the new verification key.
Two holders sign.

1. The holder who starts the signing sends the transaction's parameters and its full commitment to the other holder.
2. **Each holder computes the full commitment again** from those parameters with the transaction builder's prepare
   operation (`docs/tx-builder.md`, #123), under the stated network. Prepare reads the chain, so it runs on a
   networked machine. Only the commitment, a decimal number, goes to the share device. If it differs from the one
   sent, refuse.
3. **For a key install, each holder also checks the key.** It must be the key published in the fork notice, and the
   holder rebuilds it from the notice's source tag and compares it. Two holders who skip this can install a key that
   drains the vault.
4. Run the two rounds of `zk-toon-upgrade-key sign`, exchanging encrypted files. The result is the signature
   `{"r", "s"}`, which the transaction builder's attach operation adds to the transaction.

## The pre-fork check

**When:** within 7 days of a fork's stop slot being announced, and at least 42 days before that stop slot. That
leaves 28 days to replace a holder before the fork notice is due, 14 days before the stop slot (ADR 0006). If a fork
is announced with less notice, run the check at once: the install still needs only two working shares, and a
replacement continues after the fork. Also run it every 6 months, after the ceremony and after every re-share.

1. Each holder runs `zk-toon-upgrade-key verify-share` on the working copy and on the backup.
2. Each holder sends a fresh random contribution. `zk-toon-upgrade-key check` derives the check value from a domain
   tag, the vault's address, the date and the three contributions. A holder never signs a check value it didn't
   derive.
3. Each of the three pairs signs the check value, under the network ID the vault isn't on.
4. Add the date, the three contributions, the check value and the three signatures to the check log. With these,
   anyone can derive the check value again and verify each signature against the vault's address with `mina-signer`.

If a share fails `verify-share` but its other copy passes, make a new backup from the copy that passes. If both
copies fail, replace that holder. If a pair can't sign, the holder it shares with the other failing pair is the one
to replace. If only one pair fails, run the check again; if it fails again, refresh.

## Re-sharing and destroying old shares

A refresh gives all three holders new shares of the same key (#105). Run one after a suspected leak and after every
replacement.

1. Run `zk-toon-upgrade-key refresh` with all three holders.
2. Each holder makes a backup of the new share on new media.
3. Run the pre-fork check with the new shares. **Don't destroy anything until all three pairs of new shares have
   passed.**
4. Each holder deletes the old share from the device, physically destroys the old backup media (wiping isn't
   enough on flash), and signs a destruction statement with its communication key. The statement names the vault's
   address, the old generation number, the date and what was destroyed. Add it to the record.
5. Delete every round-message file from the channels that carried it.

Two old shares still sign together, so a refresh protects the key only once every old share and every old backup is
gone. Old message files matter too: they are encrypted to communication keys that aren't replaced, so a leaked
communication key would open them. Treat a leaked communication key as a suspected leak of that holder's share.

## Replacing a holder

A holder is replaced after a suspected leak of its share, a share lost with no working backup, a failed check, or
the holder leaving their role. The two remaining holders decide. The leaving holder's agreement isn't needed.

1. Pick the new holder. They must fit ADR 0012's roles: the operator, the TOON team, or an independent holder who
   isn't the Mina team.
2. The new holder sets up (above). Their fingerprint is checked and recorded.
3. The two remaining holders run `zk-toon-upgrade-key repair` to give the new holder a share at the leaving holder's
   identifier. That share is the leaving holder's share, so the new holder makes no backup of it and destroys it
   after the refresh like any old share.
4. All three refresh, and old shares are destroyed (above). The leaving holder is asked to destroy its share too, but
   once the other two old shares are gone, it can sign nothing alone.
5. Publish the change at the vault's zkApp URI and update the holders' record.

If two shares are lost or leaked, nothing restores the key. Announce it at the vault's zkApp URI at once: payers
should leave before the next fork's stop slot. Then deploy a new vault.
