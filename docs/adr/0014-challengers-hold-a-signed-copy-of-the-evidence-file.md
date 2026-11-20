---
status: accepted
---

# Challengers hold a signed copy of the evidence file

Issue #107, raised in the Mina team's review. A challenger defeats or raises an escape from the zk
edge's evidence file, and until now it read that file on the zk edge's own host. So whatever stopped
the zk edge stopped its challenger too. If the host was down for an escape's 2-day challenge window,
or its disk was lost, the escape went unchallenged and the operator lost up to one note. And no third
party could run a challenger.

There is a second danger, for payers. A grant record with no close record means the allowance never
closed, so the challenger raises to its tier `b` (ADR 0004). A challenger that had the grant but not
yet the close would take more than the payer owed. So a copy that falls behind can be wrong, not just
late.

## Decision

- **Each challenger holds an evidence copy**: byte for byte a prefix of the zk edge's evidence file.
  The challenger reads it exactly as it read the zk edge's file. How far behind it is comes down to
  one length.
- **The zk edge pushes as it records.** Each push is `{offset, bytes, signature}` over HTTP, sent to
  every challenger in the zk edge's configuration, through SOCKS5 if it is set. The challenger
  appends the bytes, fsyncs, and replies with its copy's length. If the offset doesn't match its
  length, it appends nothing and replies with the length, and the zk edge resends from there.
- **A record counts as recorded once `k` challengers hold it.** The zk edge grants an allowance only
  after `k` challengers confirm its grant record. It releases a signed next state only after `k`
  confirm the close record. This extends the rule that both are on disk first (ADR 0004). The other
  challengers get the push without the zk edge waiting for them. `k` defaults to 1. With `k = 0` a
  record counts once it is on disk, as before. The zk edge then logs loudly at start. That setting is
  for local development.
- **With fewer than `k` challengers reachable, the zk edge stops.** It grants nothing new and releases
  no next state until enough are back. Payers can still escape. There is no fallback to "on disk
  only" during an outage.
- **The zk edge signs every push with the state key**, over a message led by its own domain tag, as
  the clearance message is led by `toon.zk.clearance.v1`, so it never passes as a state or a
  clearance. The signature covers the vault, the copy's length after the push, and a running hash of
  every record up to that length.
  A challenger accepts only bytes that extend its copy exactly and carry a valid signature. It already
  reads the state key from the vault's state.
- **A lagging challenger catches up before it acts.** Every challenger serves its copy and the latest
  signature it holds. At the start of each pass, it asks the zk edge and then its peers for signed
  bytes past its own length.
  - A defeat, or a raise to a recorded charge, can't be made wrong by a record the copy is missing,
    so it goes ahead at once.
  - A raise to `b` waits, and the challenger keeps trying to catch up on every pass. It raises only
    once the deadline is within `2 × min-lead`, and then on the best copy it has.
- **Reading a copy takes a token.** All of the operator's challengers share a bearer token, read from
  the environment and never from a flag. Pushes need none, since the zk edge signs them.
- **The operator chooses the challengers.** They can include a third party, such as a watchtower. A
  challenger learns what the records hold: the timing, tier and subsidised flag of every allowance,
  and the per-period nullifier of a subsidised one. It doesn't learn where packets go.
- **`zk-evidence` owns the format**: the push, the signed checkpoint, the tag and the running hash, all
  pinned by shared vectors, as it already owns the file's bytes. The connector implements the
  sending side.
- **The zk edge alerts.** It exposes how many bytes behind each challenger is, and how old the oldest
  record it hasn't confirmed is. It logs when a challenger is unreachable or more than 5 minutes
  behind (configurable), and when fewer than `k` are reachable.

## Considered Options

- **Push without waiting, and alert on lag:** rejected. Records from the last moments before an edge's
  disk is lost would be lost too. A lagging challenger could also raise a payer to `b`.
- **Wait for every challenger:** rejected. Any one challenger being down would stop every grant.
- **Have challengers pull from the zk edge:** rejected. It only narrows the gap, and the zk edge
  couldn't wait for a confirmation.
- **Store records outside the file's format:** rejected. A prefix of the file needs no new reader, and
  its length shows how far behind it is.
- **Sign with a key used only for evidence:** rejected. It would be another key to manage and to
  configure in every challenger, and the state key, under its own domain tag, already authenticates
  the zk edge.
- **Carry the pushes in TOON packets:** not adopted. HTTP through an optional SOCKS5 proxy is what the
  challenger already speaks.
- **Restrict reads by network address:** rejected. Addresses are fragile behind Tor.

## Consequences

- If the challengers are unreachable, the zk edge stops serving. Running at least `k + 1` of them
  keeps it serving through one failure, so devnet runs two with `k = 1` (#110).
- Granting an allowance now waits for one HTTP round trip.
- A zk edge with several instances still needs one shared store for the nullifier set and the
  per-period nullifiers. That is the connector's issue, not this ADR's.
