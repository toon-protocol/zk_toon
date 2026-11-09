<div align="center">

# zk_toon

**Deposit once, then pay for TOON services without the service, or anyone on the path,
learning which deposit paid.**

*Payments on TOON that hide which payer paid.*

A payer deposits into a Mina vault once.<br>
It then pays with zero-knowledge proofs instead of vouchers that name its channel.

[![CI](https://img.shields.io/github/actions/workflow/status/toon-protocol/zk_toon/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/toon-protocol/zk_toon/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Network](https://img.shields.io/badge/network-Mina%20devnet-c9a24a?style=flat-square)](docs/adr/0010-the-devnet-values.md)
[![o1js](https://img.shields.io/badge/o1js-3.1.0-lightgrey?style=flat-square)](o1js/package.json)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-b7410e?style=flat-square)](https://www.rust-lang.org)

[**Design**](docs/design/zkapi-payments.md) · [**Glossary**](GLOSSARY.md) · [**Guides**](#guides) · [**Decisions**](docs/adr/) · [**Development**](docs/development.md)

```sh
git clone https://github.com/toon-protocol/zk_toon
```

</div>

---

## Three steps

**1. Install o1js.** The vault and circuits are written in it.

```sh
cd zk_toon/o1js && npm ci
```

**2. Test the vault and the circuits** on o1js's local chain.

```sh
npm test                            # includes the proofs-on set, which proves for real
```

**3. Check the Rust side against the same vectors.**

```sh
cd .. && cargo test --workspace     # every Rust crate
```

A vault on Mina devnet needs the dev funder's key. [The devnet smoke
test](docs/devnet-smoke.md) shows that run, from deposit to escape.

## What holds

- **You risk at most one allowance.** If the zk edge cheats, the most you lose is one
  allowance's budget: 1 MINA on devnet.
- **You can always leave.** The vault has no pause, and no owner can stop an escape. It pays
  after a 2-day challenge window.
- **Mina, with no trusted setup.** Mina's proofs need no ceremony. Devnet only for now:
  mainnet waits for an external review of the vault and circuits, among other gates.
- **MIT licence.** `zk-prover` is Apache-2.0.

Below: why it is built this way, how the pieces fit, the [guides](#guides).

## Why it exists

TOON already hides **what** a payer sends. It does not hide **who** pays. The first
connector checks a voucher on every packet, every voucher names the payer's channel, and the
chain links that channel to the payer's address. zk_toon splits the work in two:

- A **payer** deposits into the Mina **vault** once, which creates a **zk note**. It then
  pays with a proof that some unspent note can cover the cost, without saying which one.
- A **zk edge** is a connector that accepts these proofs. One proof buys an **allowance**, a
  small budget spent with session vouchers. Past the zk edge nothing changes.

The design holds a payer's deposit against a zk edge it does not trust:

- **Nothing names the payer.** The zk edge learns only that some note in the vault can cover
  the tier. One allowance can't be linked to another, and the app gets no payer header.
- **Nothing traps a deposit.** The vault has no pause. Its deploy makes its permissions
  unchangeable, and its verification key changeable only across a Mina hard fork ([ADR
  0006](docs/adr/0006-the-vaults-account-permissions.md)).
- **Nothing is trusted unchecked.** A client runs the vault check on a vault address and
  refuses a vault the pinned vault registry does not list ([ADR
  0008](docs/adr/0008-a-client-checks-a-vault-before-trusting-it.md), [ADR
  0011](docs/adr/0011-vaults-are-deployed-through-a-registry.md)).
- **Nothing dishonest goes unanswered.** A challenger watches the vault and defeats or
  raises a dishonest escape from the zk edge's evidence file.

## How it fits together

```
          proof, session vouchers           its own ordinary vouchers
  payer ─────────────────────────► zk edge ─────────────────────────► hop ──► app
    │                                │  knows: some note paid
    │ deposit, close, escape         │  writes: the evidence file
    ▼                                ▼
 ┌──────────────────────────┐   ┌───────────────────────────────────┐
 │ Mina vault (o1js)        │◄──┤ challenger (Rust)                 │
 │ notes, nullifiers, roots │   │ defeats or raises a dishonest     │
 │ escapes, expiry sweep    │   │ escape, through the tx builder    │
 └──────────────────────────┘   └───────────────────────────────────┘
```

A **zk note** is one deposit, spendable only by whoever knows its secret. When an allowance
closes, the zk edge charges it and signs the note's next state, a **state advance**, without
learning its balance. A payer leaves by **mutual close** with the zk edge's clearance, or by
**escape** without it. The [design](docs/design/zkapi-payments.md) walks a payment end to
end, and the [glossary](GLOSSARY.md) defines every term.

### The pieces, for reference

| Piece | What it does |
| --- | --- |
| [`o1js/`](o1js/) | The vault zkApp, the request and withdrawal circuits, the vault registry, the vault check and the transaction builder |
| [`zk-note`](zk-note/) | The hashes, nullifiers, anchors and period arithmetic the vault circuits check, byte for byte with o1js |
| [`zk-evidence`](zk-evidence/) | The evidence file's byte format: records, framing, header and evidence hash. No file I/O |
| [`zk-prover`](zk-prover/) | A Kimchi step prover for o1js circuits, on the pinned mina-rust fork |
| [`tx-builder`](tx-builder/) | The Rust client of the o1js transaction builder: proved vault transactions and request proofs |
| [`challenger`](challenger/) | The challenger's decision core and its ports |
| [`challenger-mina`](challenger-mina/) | The challenger's Mina adapter, and the `zk-toon-challenger` service |
| [`fixture-gen/`](fixture-gen/) | The code that produced `zk-prover/fixtures/` |
| [`test-vectors/`](test-vectors/) | The shared test vectors the o1js and Rust sides both check |

The connector side of the zk edge is
[toon-protocol/connector#1511](https://github.com/toon-protocol/connector/issues/1511), not
this repo.

## Guides

| Guide | What it walks through |
| --- | --- |
| [zkAPI-style payments on TOON](docs/design/zkapi-payments.md) | The problem, a payment from deposit to withdrawal, subsidised allowances, what each party learns, and the phases |
| [The transaction builder](docs/tx-builder.md) | Running the o1js process, its JSON protocol, and every operation and failure |
| [The challenger's Mina adapter](docs/challenger-mina.md) | Reading escapes and deadlines, submitting defeats and raises, and running `zk-toon-challenger` |
| [Published keys and the proofs-on set](docs/verification-keys.md) | Building the verification keys and the vault code hash, and the tests that prove for real |
| [The devnet smoke test](docs/devnet-smoke.md) | Deploying a vault and the vault registry to Mina devnet, and reproducing the sighting |
| [Lightnet tests](o1js/lightnet/README.md) | The tests that need a chain that checks proofs, on a local Docker lightnet |
| [fixture-gen](fixture-gen/README.md) | Regenerating the prover's fixtures from o1js |

## Reference

- [`GLOSSARY.md`](GLOSSARY.md): every term, with the words to avoid.
- [`docs/adr/`](docs/adr/): the decisions behind the design, and why.
- [`docs/design/scheme_batch_settlement_mina.md`](docs/design/scheme_batch_settlement_mina.md):
  the batch-settlement scheme for Mina proposed to x402.
- [`docs/research/`](docs/research/): Mina's privacy-pool landscape, token distribution and
  the vault, and cuTile Rust for the prover.
- [`docs/development.md`](docs/development.md): the toolchain, the checks the gate runs, and
  the agent factory.
