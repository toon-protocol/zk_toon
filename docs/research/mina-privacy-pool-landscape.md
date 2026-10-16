# Mina privacy-pool landscape (for the zk edge, connector #1511)

Accessed 2026-10-16. All sources were read on that date. **(inference)** marks my own reasoning. **unverified** marks a claim I could not confirm from a primary source.

## Bottom line

- **No privacy pool, mixer or shielded pool is live on Mina mainnet.** Every Mina mixer I found is a 2022–2024 hackathon or builder-programme prototype, and none has been updated since January 2024. None uses fixed denominations or an association set, none was audited, and none is deployed for real use (section 1).
- **There is no shared anonymity set, no standard note format and no Privacy Pools (association-set) implementation on Mina.** If we want an anonymity set, we have to build it (section 2).
- **Liquidity is very thin.** No stablecoin is live on Mina mainnet. The only fungible-token standard is archived and was never audited, though a newer o1Labs contract replaces it. The DEX that runs on Lumina's framework holds about 1,470 MINA on the MINA side, across five pools, all of them MINA/memecoin. The ETH→Mina bridge (Nori) has run as a testnet and is being audited, and no production bridge is live (section 3).
- **The tooling is mostly there, with one serious gap.**
  - Already there: Mesa (live on mainnet since September 2026) raised zkApp on-chain state from 8 to 32 fields. o1js has `IndexedMerkleMap` (which can prove a key is absent, so it works as a nullifier set), `BatchReducer` and an experimental `OffchainState`.
  - Mostly there: Rust `mina-hasher` and `mina-signer` can match o1js. To verify o1js's in-circuit `Signature`, the Rust side must use the "devnet" prefix, whatever network the vault is on.
  - **The gap: no maintained Rust verifier for an arbitrary o1js `ZkProgram` proof exists.** The Mina Rust node has the code, but o1Labs **paused development** in July 2026, and its public verify function only accepts zkApp transaction statements (section 4).
- **There is no Mina Foundation or o1Labs statement on mixers or privacy payments** that I could find. Their privacy work has been compliance-flavoured: zk-KYC (identity checks that keep the details private) and private attestations (section 5).
- **What we would have to build:** the vault, the note format, the nullifier set, the tiers, the Rust verifier path (fork the paused Rust node's Pickles verifier, or pin it), and the anonymity set itself. Nobody else's deposits will share our pool. **(inference)**

## 1. Privacy pools, mixers and shielded payments on Mina

| Project | What it is | Design | Status (last push) |
|---|---|---|---|
| **Minado** ([repo](https://github.com/Nicolascoding27/Zkapp-mina-ui)) | Tornado-style mixer from the zkApps Builders Program | Commitment `C = H(secret, nullifier)` stored as a leaf in an off-chain Merkle tree. To withdraw, the payer proves its leaf is in the tree with a Merkle witness ([README](https://github.com/Nicolascoding27/Zkapp-mina-ui)). The README does not say whether amounts are fixed. | Prototype. Last push 2022-11-22. **Abandoned.** |
| **Shadow** ([repo](https://github.com/Comdex/shadow)) | "A Private Account System On Mina", described as a mixer in the [Spring 2022 Builders wrap-up](https://minaprotocol.com/blog/zkapps-builders-program-spring-2022-wrapup) | Account model with registered unique names and encrypted local account data. Not a note/nullifier pool ([README](https://github.com/Comdex/shadow)). | Last push 2022-04-08. **Abandoned.** |
| **zKeeper** ([repo](https://github.com/0x471/o1js-zkeeper)) | "Token Mixer on Mina": a Protokit appchain mixer with KYC/AML | Runs as a rollup appchain, not as an L1 zkApp. "Only for research and educational purposes" ([README](https://github.com/0x471/o1js-zkeeper)). | Last push 2023-11-22. **Abandoned.** |
| **mina-privacy-coin** ([repo](https://github.com/suenchunhui/mina-privacy-coin)) | Privacy token: two Merkle trees, one of public balances and one of private balances | Private leaves hide the owner and the balance. Not a fixed-denomination pool ([README](https://github.com/suenchunhui/mina-privacy-coin)). | Proof of concept. Last push 2024-01-18. **Abandoned.** |
| **mCash** (chainwayxyz) | Mixer named in a third-party list | Repository returns 404. | **unverified**, gone |

None of these is on mainnet as a service. None publishes fixed denominations, an audit or deployment addresses. **(inference)** All of them were written before Mesa, when zkApps had only 8 on-chain fields, and the ones that are pools keep their tree off-chain.

Two adjacent tools exist but are not payment pools:
- **Protokit** is a framework for "privacy enabled application chains" (appchains: app-specific rollups on Mina) ([starter-kit](https://github.com/proto-kit/starter-kit); [Q2 2026 update](https://minaprotocol.com/blog/q2-2026-mina-ecosystem-update)).
- **mina-attestations** gives Mina wallets private credentials ([repo](https://github.com/zksecurity/mina-attestations), active 2026-10-16).

## 2. A shared anonymity set or standard note format

- I found **no standard note format, no shared pool and no association-set design** on Mina. I searched GitHub (`mina mixer`, `o1js privacy pool`, `mina shielded pool`, `o1js nullifier tornado` and similar) and found nothing beyond the projects in section 1. The Mina blog's 2025 recap and its Q1 and Q2 2026 updates do not mention mixers or shielded pools ([2025 recap](https://minaprotocol.com/blog/2025-mina-recap), [Q1 2026](https://minaprotocol.com/blog/q1-2026-update), [Q2 2026](https://minaprotocol.com/blog/q2-2026-mina-ecosystem-update)).
- **The closest building block is o1js's `Nullifier`.** It is a deterministic, key-bound nullifier (the PLUME construction, [eprint 2022/1255](https://eprint.iacr.org/2022/1255.pdf)), "used as a public commitment to a specific anonymous account, to forbid actions like double spending" ([source](https://github.com/o1-labs/o1js/blob/main/src/lib/provable/crypto/nullifier.ts)). It is tied to a Mina key. Our nullifier-chain design derives nullifiers by Poseidon, so we would not use it as is. **(inference)**
- **Privacy Pools**, in the Buterin et al. sense, publishes association sets as Merkle roots ([Privacy Pools docs](https://docs.privacypools.com/)). Its only implementation is on EVM, and no Mina port exists (**unverified** absence: I searched and found none).

## 3. Liquidity and assets

**The token standard.** Mina has custom tokens built into the protocol. A **token owner zkApp** (a contract built on `TokenContract`) is the only account that can mint, burn or approve transfers of its token. The protocol tracks the token's balances in accounts keyed by public key and token ID ([docs](https://docs.minaprotocol.com/zkapps/writing-a-zkapp/feature-overview/custom-tokens)).
- The reference fungible-token implementation, which follows RFC14, is `MinaFoundation/mina-fungible-token`. It "is currently a beta… awaiting an audit". The repository is **archived** (last push 2025-01-03) ([repo](https://github.com/MinaFoundation/mina-fungible-token)).
- o1Labs publishes a newer `FungibleToken` contract with side-loaded proofs. Its only release is 0.0.1 (2025-07-11), and its last push was 2026-02-25 ([repo](https://github.com/o1-labs-XT/fungible-token-contract)).

**Stablecoins.** None is live on Mina mainnet.
- **zkUSD** is an algorithmic stablecoin backed by MINA collateral ([core README](https://github.com/zkUSD-Protocol/core)). The Mina Foundation lists it as an ecosystem project ([June 2025 post](https://minaprotocol.com/blog/a-new-chapter-for-the-mina-ecosystem)). Its repositories were last pushed in June–August 2025 ([org](https://github.com/zkUSD-Protocol)). A devnet beta was announced on X (**unverified** from a first-party page). **(inference)** It looks dormant.
- A Mina Foundation post from 2023 mentions a feasibility study on a "compliant, privacy-preserving fiat stablecoin", which was research only ([2023-05-25](https://minaprotocol.com/blog/mina-foundation-and-etonec-announce-privacy-prototype-to-address-existing-compliance-issues-for-web3-applications-and-businesses)).
- I found no USDC or other issuer-backed stablecoin on Mina (**unverified** absence). DefiLlama tracks no Mina chain and no Mina stablecoin, which is consistent with that (DefiLlama API `/v2/chains` and `stablecoinchains`, queried 2026-10-16).

**DEXs and AMMs.**
- **Lumina** is an AMM framework and SDK; Zeko released it as "an SDK for building DEXs on Mina". **Solis** "is the first DEX to go live on mainnet using the Lumina framework" ([Q1 2026, 2026-04-16](https://minaprotocol.com/blog/q1-2026-update)). The repositories are active ([monorepo](https://github.com/Lumina-DEX/lumina), pushed 2026-10-06).
- **TVL, measured on chain.** Lumina's own pool index lists five mainnet pools: MINA/ZKA, MINA/LIGHT, MINA/Horse, MINA/TURK and MINA/TIT (`https://cdn.luminadex.com/api/mina:mainnet/pools`, route defined in [contracts-cdn](https://github.com/Lumina-DEX/lumina/blob/main/packages/contracts-cdn/src/index.ts)). I read each pool account's MINA balance from mainnet GraphQL at `api.minascan.io` (the endpoint Lumina's [SDK constants](https://github.com/Lumina-DEX/lumina/blob/main/packages/sdk/src/constants/index.ts) use). The balances are 135.4, 1,043.3, 267.1, 27.4 and 0 MINA, a total of about **1,473 MINA**. **(inference)** Counting both sides of each pool, TVL is about 2,900 MINA-equivalent, and there is no stablecoin pool at all.
- **Zeko**, an L2 rollup on Mina, "has officially launched on mainnet" ([Q2 2026, 2026-07-21](https://minaprotocol.com/blog/q2-2026-mina-ecosystem-update); [repo](https://github.com/zeko-labs/zeko)). Lumina's SDK still marks `zeko:mainnet` as `NOT_IMPLEMENTED`.

**Bridges from EVM.**
- **Nori** (ETH→Mina, trustless) checks Ethereum state proofs on Mina, using SP1 Helios proofs converted for o1js ([eth-processor](https://github.com/Nori-zk/eth-processor), [proof-conversion](https://github.com/Nori-zk/proof-conversion)).
  - Its testnet ran in October 2025 with "over 100 users and 34 locked ETH" ([2025 recap](https://minaprotocol.com/blog/2025-mina-recap)).
  - Nori is integrating Aligned Layer's Mina→ETH bridge for two-way bridging ([Q1 2026](https://minaprotocol.com/blog/q1-2026-update)).
  - "The Nori bridge is undergoing an audit with zellic… final report… expected… Q3 2026" ([Q2 2026](https://minaprotocol.com/blog/q2-2026-mina-ecosystem-update)). No mainnet launch or audit report is published (**unverified** as of today).
  - **(inference)** Nori's newest repositories are Solana and Tempo SDKs (pushed October 2026), which suggests its focus is widening beyond Mina.
- **Older efforts:** Nil Foundation's in-EVM Mina state proof is **archived** ([repo](https://github.com/NilFoundation/mina-state-proof)). LambdaClass's `mina_bridge` was last pushed 2025-11-06 ([repo](https://github.com/lambdaclass/mina_bridge)).

## 4. Tooling

**Protocol limits after Mesa.** Mesa has been on mainnet since September 2026: release `4.0.0-mainnet-mesa` was published 2026-09-03 ([releases](https://github.com/MinaProtocol/mina/releases)), and the "Welcome to Mesa" post followed on 2026-09-08 ([post](https://minaprotocol.com/?p=13528)). On 2026-10-16 the mainnet node reported commit `685030107f`, "Empty commit for 4.0.0 Mainnet Mesa Release" (GraphQL `daemonStatus`). Mesa:
- raises zkApp state "from 8 to 32 field elements" (MIP7);
- raises the per-transaction event and action limit "from 100 to 1024 field elements" (MIP8);
- triples the account updates allowed per transaction (MIP9);
- halves slot time to 90 s (MIP6) ([Mesa docs](https://docs.minaprotocol.com/network-upgrades/mesa)).

The docs page still describes the "pre-fork" values, so it has not been updated.

**State for a vault.**
- **Actions and reducer.** The hash of all actions is kept on chain, and the actions themselves are fetched "from an archive node" ([o1js docs](https://docs.o1labs.org/o1js/zkapps/actions-and-reducers)). The basic `Reducer` carries a warning in its source: it "is currently not safe to use in production… breaks if more than the hard-coded number (default: 32) of actions are pending" ([reducer.ts](https://github.com/o1-labs/o1js/blob/main/src/lib/mina/v1/actions/reducer.ts)).
- **`BatchReducer`** processes actions in fixed-size batches across several transactions, so it works around that limit ([batch-reducer.ts](https://github.com/o1-labs/o1js/blob/main/src/lib/mina/v1/actions/batch-reducer.ts)).
- **`OffchainState`** is "experimental and subject to change", sits outside the o1js stability guarantee, and keeps all its data in one Merkle map. Its state is "only available after it was settled via `settle()`" ([docs](https://docs.minaprotocol.com/zkapps/writing-a-zkapp/feature-overview/offchain-storage)). Defaults: `logTotalCapacity = 30` (about 1 billion entries) and `maxActionsPerUpdate = 4` ([offchain-state.ts](https://github.com/o1-labs/o1js/blob/main/src/lib/mina/v1/actions/offchain-state.ts)).
- **`IndexedMerkleMap`** has `assertNotIncluded`, a proof that a key is absent, which is what a nullifier set needs ([merkle-tree-indexed.ts](https://github.com/o1-labs/o1js/blob/main/src/lib/provable/merkle-tree-indexed.ts)).
- **o1js versions.** o1js is at v3.1.0 (2026-10-02) ([releases](https://github.com/o1-labs/o1js/releases)), and the Native Prover is "stable and production-ready" since 2.15.0 ([Q2 2026](https://minaprotocol.com/blog/q2-2026-mina-ecosystem-update)).

**Archive node dependency.** **(inference)**
- Reading the *current* vault root and other on-chain fields needs only a daemon's GraphQL endpoint.
- Answering "is this a root the vault has held?" or "is this nullifier spent on chain?" needs either the action history from an archive node, or a ring of recent roots kept in the 32 on-chain fields.

**Rust verification of o1js proofs (the main gap).**
- The Mina Rust node (`o1-labs/mina-rust`, formerly openmina; `o1-labs/openmina` redirects there) states: "Development of the Mina Rust Node is currently paused… there is currently no committed timeline for future releases or mainnet deployment" ([README](https://github.com/o1-labs/mina-rust)). That notice was added 2026-07-15. The last release is v0.19.0 (2026-01-20).
- Its public Pickles verifier for zkApps is `verify_zkapp(verification_key, zkapp_statement: &ZkappStatement, sideloaded_proof, srs)`, which takes a *zkApp account-update* statement. The generic `verify_impl<AppState: ToFieldElements<Fp>>` underneath it is private ([verification.rs](https://github.com/o1-labs/mina-rust/blob/develop/crates/ledger/src/proofs/verification.rs)).
- **(inference)** Verifying a `ZkProgram` proof with our own public inputs in Rust means forking or vendoring this crate and exposing `verify_impl`. Whether the paused code matches proofs from o1js 3.x after Mesa is **unverified**, so it needs a test vector.
- `proof-systems` (kimchi, the Pasta curves, Poseidon) is active (last push 2026-10-07, release 0.7.0 on 2026-04-15) ([repo](https://github.com/o1-labs/proof-systems)). It does not include a Pickles verifier.

**Poseidon and Schnorr compatibility.**
- `mina-hasher` wraps Mina's Poseidon. Its kimchi hasher is labelled "experimental". When a domain string is given, it absorbs `domain_prefix_to_field(domain)` first; with none, it starts from the zero state ([README](https://github.com/o1-labs/proof-systems/blob/master/hasher/README.md), [poseidon.rs](https://github.com/o1-labs/proof-systems/blob/master/hasher/src/poseidon.rs)). **(inference)** That matches o1js `hashWithPrefix` and `Poseidon.hash` respectively.
- `mina-signer` has `NonceMode::Chunked`, documented as "compatible with the TypeScript o1js implementation" ([lib.rs](https://github.com/o1-labs/proof-systems/blob/master/signer/src/lib.rs), [schnorr.rs](https://github.com/o1-labs/proof-systems/blob/master/signer/src/schnorr.rs)).
- **Catch:** o1js's in-circuit `Signature.create` and `verify` hard-code `signaturePrefix('devnet')`. The source comment says "the signatures can be used with any network" ([signature.ts](https://github.com/o1-labs/o1js/blob/main/src/lib/provable/crypto/signature.ts)). So the zk edge's Rust signer must sign successor states with the testnet/devnet network ID, even for a mainnet vault, or the vault circuit will reject them. **(inference)** Pin both of these with byte-level test vectors.

## 5. Grants, programmes and statements

- o1Labs runs the grants programme ([June 2025](https://minaprotocol.com/blog/a-new-chapter-for-the-mina-ecosystem)). The Mina Builders Grants Program launched in 2025 and is "a selective program with funding matched to project stage" ([2025 recap](https://minaprotocol.com/blog/2025-mina-recap)). I found no request for proposals for privacy payments (**unverified** absence).
- The Foundation's privacy work has been about compliance: it funded a zk-KYC/AML identity prototype for Lumina in 2023 ([post](https://minaprotocol.com/blog/mina-foundation-and-etonec-announce-privacy-prototype-to-address-existing-compliance-issues-for-web3-applications-and-businesses)), and its marketing describes "programmable privacy" ([roadmap](https://minaprotocol.com/roadmap)).
- **I found no Mina Foundation or o1Labs statement on mixers or their regulatory status** (**unverified** absence). Both Lumina and zKeeper chose KYC-flavoured designs.

## Implications for the zk edge / issue #1511

All of this section is **(inference)**.

1. **We start the anonymity set at zero.** No existing pool, note format or set of users exists to join. With one MINA/memecoin DEX holding about 1.5k MINA and no stablecoin, few independent depositors will arrive on their own.
   - Plan for small sets: few tiers, long allowance lifetimes, and guidance to deposit well ahead of use.
   - Make the anonymity set visible to payers: show the count of live unspent notes per tier, so a payer can tell when privacy is weak.
2. **Our "fixed-size amounts" can only be denominated in MINA for now.** A stablecoin tier would wait on zkUSD (dormant) or on a bridged asset (Nori, not in production). MINA price swings will move the tiers' value.
3. **Design the vault for Mesa's 32 fields.** Keep the note-tree root, the nullifier-set root (`IndexedMerkleMap` with `assertNotIncluded`) and a short ring of recent roots on chain. The ring lets the zk edge answer "a root the vault has held" without an archive node.
   - Use `BatchReducer`, not `Reducer`, for deposits.
   - Treat `OffchainState` as experimental: pin the o1js version, or avoid it.
4. **The "Rust-only verifier" decision is the riskiest part of #1511.** The only Rust Pickles verifier sits in a paused repository, behind a function that only takes zkApp statements. Budget for one of these:
   - (a) vendoring and exposing `verify_impl` from `mina-rust`, pinned, with a cross-check against o1js 3.x on every o1js upgrade; or
   - (b) relaxing "no Node beside the binary" to allow a pinned o1js verifier sidecar.

   This needs a spike before the ADR.
5. **Signer compatibility needs one explicit rule in the primitives crate:** successor-state signatures use `mina-signer` with the chunked nonce and the devnet/testnet network ID, matching o1js `Signature.verify`. Back it with a shared test vector.
6. **On regulation, Mina gives us no cover.** The ecosystem leans toward compliance. A future association-set layer (Privacy Pools) is an option we would also have to build.

## Sources

Official and project primary sources: 
- https://minaprotocol.com/blog/q1-2026-update
- https://minaprotocol.com/blog/q2-2026-mina-ecosystem-update
- https://minaprotocol.com/blog/2025-mina-recap
- https://minaprotocol.com/blog/a-new-chapter-for-the-mina-ecosystem
- https://minaprotocol.com/?p=13528 ("Welcome to Mesa")
- https://minaprotocol.com/blog/zkapps-builders-program-spring-2022-wrapup
- https://minaprotocol.com/blog/mina-foundation-and-etonec-announce-privacy-prototype-to-address-existing-compliance-issues-for-web3-applications-and-businesses
- https://minaprotocol.com/roadmap
- https://docs.minaprotocol.com/network-upgrades/mesa
- https://docs.minaprotocol.com/zkapps/writing-a-zkapp/feature-overview/offchain-storage
- https://docs.minaprotocol.com/zkapps/writing-a-zkapp/feature-overview/custom-tokens
- https://docs.o1labs.org/o1js/zkapps/actions-and-reducers
- https://github.com/MinaProtocol/mina/releases
- https://github.com/o1-labs/o1js (reducer.ts, batch-reducer.ts, offchain-state.ts, merkle-tree-indexed.ts, nullifier.ts, signature.ts, releases)
- https://github.com/o1-labs/mina-rust (README, crates/ledger/src/proofs/verification.rs)
- https://github.com/o1-labs/proof-systems (hasher, signer)
- https://github.com/MinaFoundation/mina-fungible-token
- https://github.com/o1-labs-XT/fungible-token-contract
- https://github.com/zkUSD-Protocol/core
- https://github.com/Lumina-DEX/lumina
- https://github.com/zeko-labs/zeko
- https://github.com/Nori-zk/eth-processor
- https://github.com/Nori-zk/proof-conversion
- https://github.com/lambdaclass/mina_bridge
- https://github.com/NilFoundation/mina-state-proof
- https://github.com/Nicolascoding27/Zkapp-mina-ui
- https://github.com/Comdex/shadow
- https://github.com/0x471/o1js-zkeeper
- https://github.com/suenchunhui/mina-privacy-coin
- https://github.com/proto-kit/starter-kit
- https://github.com/zksecurity/mina-attestations
- https://docs.privacypools.com/
- https://eprint.iacr.org/2022/1255.pdf

On-chain and dashboard reads (2026-10-16):
- Mina mainnet GraphQL `https://api.minascan.io/node/mainnet/v1/graphql`: `daemonStatus`, and the account balances of the five Lumina pools.
- Lumina pool index: `https://cdn.luminadex.com/api/mina:mainnet/pools`.
- DefiLlama API (`api.llama.fi/v2/chains`, `stablecoins.llama.fi/stablecoinchains`): lists no Mina chain.
