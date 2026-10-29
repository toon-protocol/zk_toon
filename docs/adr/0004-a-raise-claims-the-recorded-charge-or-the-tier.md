---
status: accepted
---

# A raise claims the recorded charge, or the tier if the allowance never closed

A raise lifts an escape's concession to `min(claimed, b, balance)`. The vault checks the request
proof but can't check `claimed`, so the zk edge could always claim the tier `b`. We don't. The
challenger claims the **charge** from the allowance's close record in the evidence file. When an
allowance has a grant record and no close record, it never closed, and the challenger claims `b`:
the most a payer accepted when it opened that allowance.

So a zk edge writes and fsyncs a close record **before** it releases the signed next state. If the
order were reversed, a crash between the two would leave no charge on disk, and the challenger would
claim `b` from a payer who owed less.

## Considered Options

- **Always claim `b`:** rejected. An honest zk edge would take more than it's owed from every payer
  who escapes, and escaping would cost a full allowance even when little was used.
- **Prove the charge with the highest session voucher:** not adopted. The vault can't check a
  session voucher, so it would help only an audit and not the raise.
