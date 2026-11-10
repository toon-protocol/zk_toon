# Development

## Toolchain

- Rust 1.92, pinned in `rust-toolchain.toml`.
- Node 22, for the o1js package in `o1js/`. o1js is pinned to 3.1.0.

The Rust workspace is `challenger`, `challenger-mina`, `tx-builder`, `zk-evidence`,
`zk-note` and `zk-prover`. `zk-prover` builds mina-rust from the pinned fork ([ADR
0003](adr/0003-mina-rust-via-a-pinned-fork.md)), so a first build is slow. Its tests are
built with `opt-level = 3`: unoptimised, its witness and proof take minutes.

## The checks

The gate is the `gate` job of [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). It
runs these steps in order. Install o1js first: the transaction builder's Rust tests start
it.

```sh
cd o1js && npm ci                              # o1js install
cd .. && cargo test --workspace -- --nocapture # Rust vectors
cd o1js && npm run typecheck && npm test       # o1js vectors
npm run proofs-on -- <vitest JSON report>      # the proofs-on set
npm run keys -- <out.json>                     # the verification keys, built twice
```

- **Vectors.** Each vector step fails unless its log reports `vector cases run:` with a
  count above zero.
- **The proofs-on set** fails if any of its tests is missing, skipped or failed. The set is
  `PROOFS_ON` in `o1js/src/proofs-on.ts`.
- **The verification keys** are built with o1js's key cache and again with `--no-cache`. The
  two files must be identical, and the first is uploaded as the run's `verification-keys`
  artifact. [Published keys and the proofs-on set](verification-keys.md) has the details.

## Tests the gate does not run

- **Lightnet tests**, against a chain that checks proofs:
  [`o1js/lightnet/README.md`](../o1js/lightnet/README.md).
- **The prover's fixtures**, regenerated from o1js:
  [`fixture-gen/README.md`](../fixture-gen/README.md).
- **The devnet smoke test**, which pays from the dev funder:
  [`devnet-smoke.md`](devnet-smoke.md).

## The agent factory

An issue labelled `ready-for-agent` is implemented, reviewed and gated by
`.github/workflows/agent-implement.yml`, which opens a PR for a human to merge.
[`CLAUDE.md`](../CLAUDE.md) describes it, and [`docs/agents/`](agents/) holds the issue
tracker and triage labels.
