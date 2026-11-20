# upgrade-key

The upgrade key as a 2-of-3 FROST key over Pallas (ADR 0012, #104): a thin crate over `frost-bluepallas`, checked
against this workspace's pinned `mina-signer`. `frost-bluepallas` and `mina-tx` are pinned to
`Raspberry-Devs/mina-multi-sig@e9b5ffc`. They build on proof-systems tag `0.3.0`; this workspace stays on `ab84160`,
and values cross as field elements and base58.

`cargo test -p upgrade-key -- --nocapture` runs the tests. The trusted-dealer split is behind the `test-utils` feature.

## Changes from `1457cdd` (Veridise's audit) to `e9b5ffc`

In `frost-bluepallas/src` and `mina-tx`'s `bluepallas_compat` and `pallas_message` modules (plus the
`MalformedGroupElement` error in `mina-tx/src/errors.rs`), each matched to a finding in `audits/VAR_Nori_260615_multisig_V2.pdf`:

| Change | Finding |
| --- | --- |
| `frost-bluepallas/src/lib.rs`: `group_commitment_affine` rejects an identity group commitment before the y-coordinate is read; both `pre_commitment_*` use it | V-MSIG-VUL-003 (group commitment lacks a nonzero check) |
| `pallas_message.rs`: `translate_pk` rejects the identity; `message_hash` returns `Result` and rejects an identity public key; `challenge` rejects an identity R | V-MSIG-VUL-001 (missing point-at-infinity checks before coordinate access) |
| `pallas_message.rs`: `deserialize` bound `<` becomes `<=` for a custom network name, so a message ending at the name no longer panics | V-MSIG-VUL-002 (custom network parsing can panic) |
| `frost-bluepallas/src/lib.rs`: `SignatureSerialization` becomes `[u8; GROUP_SIZE + FIELD_SIZE]` | V-MSIG-VUL-004 (incorrect signature serialization size) |
| `pallas_message.rs`: the raw-bytes fall-through in `challenge` is compiled only with `raw-message-fallback` | V-MSIG-VUL-005 (undesirable message deserialization fallback) |
| `pallas_message.rs` `translate_sig` and `bluepallas_compat.rs` `Sig::try_from` reject an R with an odd y; new `MalformedGroupElement` error | V-MSIG-VUL-006 (signature conversion does not validate y parity) |

Every change matches a finding; none is unmatched. The other commits in the range touch dependency versions, docs and
tests only.

This crate enables neither `raw-message-fallback` nor anything else beyond `frost-bluepallas-compat`.

## Result

No disagreement between `frost-bluepallas` and the pinned `mina-signer` showed up: every threshold signature verifies
under the pinned `mina_signer::create_kimchi(network).verify` for its own network ID and not the other's.
