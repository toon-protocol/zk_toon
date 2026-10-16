# Token distribution and the vault

Sources accessed 2026-10-16. Context: the zk edge spec, [toon-protocol/connector#1511](https://github.com/toon-protocol/connector/issues/1511), and [docs/design/zkapi-payments.md](../design/zkapi-payments.md).

Labels: **(inference)** marks my own reasoning. **unverified** marks a claim I could not confirm from a primary source.

## Bottom line

The vault needs **effective** anonymity. That means the unspent notes of one size that the adversary does not control. The adversary that matters most is the zk edge operator, or anyone colluding with it. A reward helps only if three things hold. The cheapest way to collect it must be to act like a real, independent user. Claiming it must not single out a note. And it must not subsidise the adversary filling the vault with its own notes **(inference)**.

| Strategy | Grows the real crowd? | Sybil risk | Linkability of the claim | Regulatory risk | Verdict |
|---|---|---|---|---|---|
| Public deposit rewards / address airdrop (TORN 2020 style) | No. It pays capital, not people | High | High: paid to the depositing address | High | **Against** |
| Anonymity mining with public, amount-revealing claims (TORN AP) | Weakly | High | Proven leak: 358 reveals (Tutela) | High | **Against** |
| zk "held a note ≥ T days" claim, fixed amount per period, paid inside the vault | Yes, if gated | Medium without personhood | Low, if every claim is identical and batched | Medium | **Fits, with gating** |
| Reward through an exchange rate (Penumbra) or epoch conversion (Namada) | Yes: rewards everyone pro rata | Medium. Splitting pays nothing extra, but a whale still fills the set | None for the rate. Depends on what conversion reveals | Medium | **Fits; best on linkability** |
| Personhood gate (World ID, zkPassport, Zupass, Mina Attestations) on any of the above | Yes: caps one share per human | Low to medium | Low, if scoped nullifiers are used | Medium: identity vendors | **Fits, as a modifier** |
| Association-set eligibility (Privacy Pools) | Neutral to slightly smaller | n/a | Low | Lower | **Fits, as a filter** |
| Retroactive, unannounced zk airdrop to past note holders (Stealthdrop-like) | Once | Low the first time, then anticipated | Low, if the claim is in zk with deterministic nullifiers | Medium | **Fits once** |
| Pay TOON fees with the token, or a non-transferable fee credit (Aztec Fee Juice) | Indirectly: real use | None: users pay | Low, if paid from the note | Low to medium | **Fits** |
| Operator and challenger bonds / staking | Indirectly: more zk edges, safer exits | None | None: no note touched | Medium | **Fits** |
| Fee-sharing to token stakers (Railgun, Tornado relayer registry) | No | n/a | None | Higher: profit from a privacy service | **Neutral to against** |
| Burn of fees | No | n/a | None | Medium | **Neutral** |
| Protocol dev fund (Zcash) | No, directly | n/a | None | Low to medium | **Neutral** |

## 1. Privacy-preserving claims and airdrops

**Mechanism.** A *nullifier-based claim* is a zero-knowledge proof of two things: "I own some member of this public set", and "here is a value derived from my secret and a scope that I can publish only once". Nobody learns which member made the claim, but a second claim in the same scope is rejected.

- **Semaphore** is the standard form. A *group* is "a Merkle tree in which each leaf is an identity commitment". The *nullifier* is the hash of the *scope* (a topic, on which "users can generate a valid proof only once") and the identity's private key ([Semaphore glossary](https://docs.semaphore.pse.dev/glossary)). For TOON, the vault's note tree already is the group. A reward claim is the same proof as an allowance, with a different domain tag and scope **(inference)**.
- **StealthDrop** (0xPARC) is an anonymous airdrop. The claimant proves that an ECDSA key in a published Merkle tree signed a message, publishes a hash of the signature as the nullifier, and redeems to a fresh address ([repo](https://github.com/stealthdrop/stealthdrop)). Its README lists the lessons. A vulnerability led the authors to the PLUME deterministic-nullifier scheme. The leaf list is public. "Multi-token rewards would reduce the anonymity set". Relayers pay the gas by incentive, not by guarantee ([repo](https://github.com/stealthdrop/stealthdrop)). For TOON, the nullifier must be a deterministic function of the note secret (Poseidon), never of a signature **(inference)**.
- **Shielded incentives.** Penumbra and Namada pay rewards *inside* the shielded pool, so no public payout exists to link (see §3). Zcash has no shielded reward: its dev fund pays developers, not holders ([ZIP 1014](https://zips.z.cash/zip-1014)).

**Linkability rules (inference).** A claim hides its note only if it looks like every other claim. So: a fixed amount per period, not per-note accruals; claims accepted in batch windows, not instantly; paid into the vault (a credit to a note, or a new note of the standard size), never to a public address; and submitted over the same overlay route as allowances.

## 2. Rewards for note duration, and stopping farming

**Mechanism.** A *proof-of-holding reward* pays a note for staying unspent, or staying in the vault, for at least T. The owner proves "my note's deposit leaf sits under a root that is at least T old, I hold its current state, and here is my nullifier for period p".

**What it does to the crowd (inference).** Idle notes do count in the allowance proof, because the proof hides which leaf is spent. So a farmer's notes *do* hide honest users from everyone except the farmer. The danger is concentration. If one party holds 90% of the notes, the set against that party is the other 10%. If that party is, or colludes with, the zk edge operator, the reward has paid the adversary to shrink the set. Per-note rewards are therefore the wrong unit. The right unit is per independent person, capped.

**Anti-farming levers:**

- **Deposit cost.** Fixed note sizes plus Mina fees make each note cost something. That does not stop a well-funded farmer **(inference)**.
- **Lockup and minimum age.** A minimum age T means a reward cannot be earned by cycling deposits. It also pushes deposits away from use, which is what the privacy needs. Namada's spec has the same aim. Incentives "should not incentivise transactions which do not meaningfully contribute" ([Namada spec](https://specs.namada.net/modules/masp/shielded-pool-incentives)).
- **Rate limit.** A cap on the total reward per period (Penumbra's tournament has "a constant, top-level parameter controlling the rate of incentives", [forum UIP](https://forum.penumbra.zone/t/uip-liquidity-tournament/159)). Add a concave payout, where the reward stops growing past one note per person **(inference)**.
- **Proof of personhood.** A *proof of personhood* is a credential that one real human holds, used through a scoped nullifier so that each human can act once per scope.
  - *World ID:* the Orb gives the "highest-assurance uniqueness signal", and "proofs are unlinkable across apps" ([World docs](https://docs.world.org/world-id/overview)). A nullifier is unique per user, app and action ([concepts](https://docs.world.org/world-id/concepts)).
  - *Human Passport* (formerly Gitcoin Passport) scores an address from "Stamps" in order to "protect access or classify addresses" ([docs](https://docs.passport.human.tech/)). It is tied to an address, so it would link the claim to that address unless it is wrapped in a zk credential **(inference)**.
  - *Zupass* stores proof-carrying data, such as event tickets and Semaphore identities ([repo](https://github.com/proofcarryingdata/zupass)).
  - *ZKPassport* proves facts from passport chips. A domain- and scope-scoped unique identifier is reported in a third-party write-up only (**unverified**; its docs pages did not load).
  - *Mina Attestations* (zkSecurity) is the Mina-native option. Its credentials can be native (Mina-signed) or imported (zkPass, ECDSA; "zk passport" is WIP). It claims "two different presentations of the same credential, or by the same user, cannot be linked", and binds presentations to a context, including a `zk-app` context ([repo](https://github.com/zksecurity/mina-attestations)). Its README does not mention nullifiers, so a one-per-human scope would have to be built on top of it **(inference)**. zkPass is a zkTLS oracle, one of the zkOracle teams Mina Foundation selected (via a [Mina Core Grants RFP](https://github.com/MinaFoundation/Core-Grants/issues/22); details of the integration are **unverified**).

## 3. Precedents

**Tornado Cash TORN.**

- **Allocation.** 5% airdrop to addresses that deposited before block 11400000, weighted by size and age. 10% to anonymity mining over one year. 55% to the DAO treasury. 30% to the team ([TORN doc](https://github.com/tornadocash/docs/blob/en/general/torn.md)).
- **Mining design.** Mining ran 2020-12-18 to 2021-12-18, paying "a fixed amount of AP per block" while a deposit stayed in the pool ([doc](https://github.com/tornadocash/docs/blob/en/tornado-cash-classic/anonymity-mining.md)). The claim was a zk proof over the deposit and withdrawal trees. It credited a shielded AP account, and published a "reward nullifier", the Poseidon hash of the note nullifier ([reward circuit](https://github.com/tornadocash/docs/blob/en/circuits/anonymity-mining/mining-rewards.md)). Claims needed the note *already withdrawn*, and AP was swapped for TORN through an AMM to a chosen address. The docs warn that small deposits did not earn back their gas ([doc](https://github.com/tornadocash/docs/blob/en/tornado-cash-classic/anonymity-mining.md)).
- **Outcome.** The Tutela paper found that because "the AP yields were public and fixed", a user who claimed everything to one address revealed the exact block duration. That linked a unique deposit and withdrawal pair: 358 reveals from this heuristic ([Wu et al.](https://arxiv.org/pdf/2201.06811)). Lesson: a shielded reward account is not enough if the amount out encodes the duration **(inference)**.
- **Governance attack.** In May 2023 a proposal posing as an earlier one used a hidden self-destruct to swap in code that granted about 1.2M votes and drained TORN. Only press reports were reachable ([The Block](https://www.theblock.co/post/231637/attacker-uses-malicious-proposal-to-take-over-tornado-cash-governance)); the forum post-mortem did not load, so the exact figures are **unverified**. Lesson: a cheap, thin governance token makes the protocol capturable **(inference)**.

**Railgun RAIL.** Lock RAIL to vote and to earn. "Protocol deductions of 0.25%" on shield and unshield go to treasury contracts, and "distribution to RAIL stakers happens autonomously, on a fixed schedule" ([Railgun docs](https://docs.railgun.org/wiki/rail-token/protocol-governance)). It is fee-sharing, with no reward for staying shielded.

**Penumbra.** Penumbra "eliminates staking rewards entirely" in favour of an "epoch-varying exchange rate" on delegation tokens. All delegations to a validator "are fungible" ([protocol spec](https://protocol.penumbra.zone/main/stake.html)). Delegations are private, and only each validator's pool total is public ([guide](https://guide.penumbra.zone/staking)). Its Liquidity Tournament pays shielded-DEX liquidity providers and voting delegators from a fixed-rate community pool. Rewards are issued as pre-bonded delegation tokens ([UIP](https://forum.penumbra.zone/t/uip-liquidity-tournament/159)). The model to copy: no claim event, so nothing to link.

**Namada MASP rewards** (the closest precedent).

- **Funding and control.** "Up to 10% per annum inflation of NAM" funds shielded-pool rewards. Per-asset PD controllers target governance-set shielded amounts ([spec](https://specs.namada.net/modules/masp/shielded-pool-incentives)).
- **Mechanism.** On deposit, "the current epoch is appended to the asset type". Users later claim through the *convert circuit*, which turns an old-epoch asset into the current epoch plus NAM, using public "allowed conversion" rules ([spec](https://specs.namada.net/modules/masp/shielded-pool-incentives), [convert circuit](https://specs.namada.net/modules/masp/convert-circuit)). The convert circuit's public inputs are only an anchor and a value commitment ([convert circuit](https://specs.namada.net/modules/masp/convert-circuit)). Whether a conversion reveals the epoch is not stated: **unverified**.
- **Status.** The mainnet page describes Phase 4: "Shielding rewards for governance-enabled IBC assets are live" ([namada.net](https://namada.net/mainnet-launch)). Activation date and asset list (reported as USDC, ATOM, OSMO, TIA and their liquid-staked forms, mid-2025) are **unverified**.
- **Measured effect.** None found on anonymity-set quality.

**Aztec.**

- **Token.** AZTEC is used for fees, staking and governance. Fees are paid in "Fee Juice, a non-transferable asset created by bridging $AZTEC". Rewards are split 70% to sequencers and 30% to provers ([Aztec docs](https://docs.aztec.network/participate/token)).
- **No privacy incentive.** No reward for private usage is described ([Aztec docs](https://docs.aztec.network/participate/token)).
- **Sale.** ZKPassport was reportedly used in the Aztec token sale (**unverified**).

**Zcash dev fund.** 20% of the block subsidy went to the Bootstrap Project (35%), the Zcash Foundation (25%) and Major Grants (40%), from 2020 to 2024 ([ZIP 1014](https://zips.z.cash/zip-1014)). From November 2024: 12% to a lockbox and 8% to Zcash Community Grants ([ZIP 1015](https://zips.z.cash/zip-1015)). ZIP 1016 proposes a coinholder-voted fund ([ZIP 1016](https://zips.z.cash/zip-1016), status "Proposed"; whether it has been activated is **unverified**). It funds builders, not the shielded set.

**Privacy Pools.**

- **Paper.** Buterin, Illum, Nadler, Schär and Soleimani propose *association sets*. A withdrawer proves membership in a subset of deposits that excludes known-bad ones, aiming at a "separating equilibrium between compliant and non-compliant withdrawals" ([paper, BCRA 5 (2024) 100176](https://doi.org/10.1016/j.bcra.2023.100176)).
- **0xbow deployment.** An *Association Set Provider* maintains "a set of approved deposits". *Ragequit* lets unapproved depositors exit publicly ([0xbow docs](https://docs.privacypools.com/)). There is no token or incentive in those docs. The mainnet launch of 2025-03-31 is per [The Block](https://www.theblock.co/post/348959/privacy-pools-vitalik-buterin) (secondary).
- **For TOON.** Ragequit is the analogue of TOON's concession escape exit **(inference)**.

## 4. Fee and utility designs

- **Pay fees in the token, or a fee credit.** A *fee token* is spent to buy service. Demand comes from use, and a farmer must pay to take part. A *non-transferable* credit, like Aztec's Fee Juice ([docs](https://docs.aztec.network/participate/token)), cannot be dumped on a thin market, so it avoids swap linkability and price swings **(inference)**. If the credit lives inside the note (a balance in the vault), paying fees leaks nothing new **(inference)**.
- **Operator bonds.** A *bond* is stake that can be slashed if the operator cheats. A zk edge could bond the token to cover its open-allowance exposure (#1511's cap), and challengers could bond to back their escape disputes. That touches no note. Precedents: Tornado's relayer registry required staking TORN ([Van Loon opinion](https://www.ca5.uscourts.gov/opinions/pub/23/23-50669-CV0.pdf)), and Aztec sequencers stake ([docs](https://docs.aztec.network/participate/token)). More, safer zk edges help the crowd only indirectly **(inference)**.
- **Fee-sharing or burn.** *Fee-sharing* pays a cut of usage fees to token stakers (Railgun, [docs](https://docs.railgun.org/wiki/rail-token/protocol-governance)). In Tornado, the relayer registry "collects a fee from the relayer and pays it to the TORN token holders" who lock in governance ([Van Loon opinion](https://www.ca5.uscourts.gov/opinions/pub/23/23-50669-CV0.pdf)). A *burn* destroys fees instead. Neither grows the set. Fee-sharing ties token holders' income to the privacy service's volume (see §5).

## 5. Regulatory facts (facts only, not legal advice)

- **2022-08-08:** OFAC designated Tornado Cash under E.O. 13694. It said the mixer laundered "more than $7 billion" since 2019, including "over $455 million stolen by the Lazarus Group" ([Treasury jy0916](https://home.treasury.gov/news/press-releases/jy0916)).
- **2024-11-26, Van Loon v. Treasury (5th Cir., No. 23-50669):** "Tornado Cash's immutable smart contracts … are not the 'property' of a foreign national or entity", so they "cannot be blocked under IEEPA". The opinion separates the immutable pools from the mutable governance and relayer-registry contracts, and describes TORN fees flowing to locked holders. Its holding concerns the immutable contracts ([opinion](https://www.ca5.uscourts.gov/opinions/pub/23/23-50669-CV0.pdf)).
- **2025-03-21:** Treasury removed the sanctions "as reflected in Treasury's Monday filing in Van Loon". It framed this as discretion after review, and said it remains "deeply concerned" about DPRK laundering ([Treasury sb0057](https://home.treasury.gov/news/press-releases/sb0057)).
- **Roman Storm (S.D.N.Y. 1:23-cr-00430, [docket](https://www.courtlistener.com/docket/67720764/united-states-v-storm/)):**
  - *Verdict.* Convicted in August 2025 of conspiring to operate an unlicensed money-transmitting business ([DOJ release](https://www.justice.gov/usao-sdny/pr/founder-tornado-cash-crypto-mixing-service-convicted-knowingly-transmitting-criminal)). The page was bot-blocked; its title and content were confirmed through a search index only. The jury hung on money laundering and sanctions conspiracy (press reports; **unverified** against the docket).
  - *Retrial.* Reported as set for 2027-04-26, with a Rule 29 motion pending ([The Block](https://theblock.co/news/regulation/2026-08-26-tornado-cash-roman-storm-retrial-april-2027-412761); **unverified**).
- **Samourai Wallet:**
  - *Sentences.* Rodriguez got five years (2025-11-06) and Hill four years (2025-11-19).
  - *Amounts.* Prosecutors cited over $237M of criminal proceeds. The defendants forfeited $6,367,139.69, which "represents those fees" ([IRS-CI release](https://www.irs.gov/compliance/criminal-investigation/founders-of-samourai-wallet-cryptocurrency-mixing-service-sentenced-to-five-and-four-years-in-prison); [DOJ](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-sentenced-five-and-four-years)).

**What bears on a TOON token (inference).** Both prosecutions centred on operators who ran or profited from the service. The only court ruling favourable to the protocol covered *immutable* code, and the opinion itself names the TORN governance and fee contracts as mutable. A token that governs the vault, or collects its fees, is closer to the mutable side than the vault circuit is.

## Recommendation for TOON (inference, clearly marked)

1. **Do not tie a tradeable token to deposits.** No per-deposit or per-note payouts, and no anonymity mining that pays a public, duration-encoding amount. TORN shows both failure modes.
2. **Put the token, if there is one, on the operator side.** Use it for zk edge bonds sized to the open-allowance cap and for challenger bonds. Optionally, let fees be payable in it. Prefer burn to fee-sharing, and avoid governance over the vault's verification key, which is the capture risk Tornado showed.
3. **Grow the crowd with a holding subsidy that lives inside the vault, not with the token:**
   - one fixed credit per period, in the vault's own asset, to any note at least T old;
   - claimed with a vault proof plus a per-person, per-period nullifier from a personhood credential (Mina Attestations in a `zk-app` context, wrapping zkPassport or World ID);
   - accepted in batch windows;
   - paid as an increment to the note's committed balance;
   - capped in total, like Penumbra's fixed rate.

   Better still, if the vault circuit allows it: a Penumbra-style rate on every note, with no claim at all. Check first that it does not reveal deposit epochs, which is the open question in Namada's design.
4. **Consider association-set eligibility** for the subsidy only, not for spending. That lowers regulatory exposure without fragmenting the spend set.
5. **Measure effective anonymity.** Count independent, personhood-backed holders, not notes, and publish the count with each tier.

## Sources

- connector#1511 spec: https://github.com/toon-protocol/connector/issues/1511
- Semaphore glossary: https://docs.semaphore.pse.dev/glossary
- StealthDrop: https://github.com/stealthdrop/stealthdrop
- World ID: https://docs.world.org/world-id/overview , https://docs.world.org/world-id/concepts
- Human Passport: https://docs.passport.human.tech/
- Zupass: https://github.com/proofcarryingdata/zupass
- Mina Attestations: https://github.com/zksecurity/mina-attestations
- Mina Core Grants zkPass RFP: https://github.com/MinaFoundation/Core-Grants/issues/22
- Tornado TORN: https://github.com/tornadocash/docs/blob/en/general/torn.md
- Tornado anonymity mining: https://github.com/tornadocash/docs/blob/en/tornado-cash-classic/anonymity-mining.md , https://github.com/tornadocash/docs/blob/en/circuits/anonymity-mining/mining-rewards.md
- Wu et al., Tutela: https://arxiv.org/pdf/2201.06811
- The Block, governance attack (secondary): https://www.theblock.co/post/231637/attacker-uses-malicious-proposal-to-take-over-tornado-cash-governance
- Railgun governance: https://docs.railgun.org/wiki/rail-token/protocol-governance
- Penumbra: https://protocol.penumbra.zone/main/stake.html , https://guide.penumbra.zone/staking , https://forum.penumbra.zone/t/uip-liquidity-tournament/159
- Namada: https://specs.namada.net/modules/masp/shielded-pool-incentives , https://specs.namada.net/modules/masp/convert-circuit , https://namada.net/mainnet-launch
- Aztec token: https://docs.aztec.network/participate/token
- Zcash: https://zips.z.cash/zip-1014 , https://zips.z.cash/zip-1015 , https://zips.z.cash/zip-1016
- Privacy Pools paper: https://doi.org/10.1016/j.bcra.2023.100176 ; 0xbow docs: https://docs.privacypools.com/ ; launch (secondary): https://www.theblock.co/post/348959/privacy-pools-vitalik-buterin
- Treasury: https://home.treasury.gov/news/press-releases/jy0916 , https://home.treasury.gov/news/press-releases/sb0057
- Van Loon opinion: https://www.ca5.uscourts.gov/opinions/pub/23/23-50669-CV0.pdf
- US v. Storm: https://www.justice.gov/usao-sdny/pr/founder-tornado-cash-crypto-mixing-service-convicted-knowingly-transmitting-criminal , https://www.courtlistener.com/docket/67720764/united-states-v-storm/ ; retrial (secondary): https://theblock.co/news/regulation/2026-08-26-tornado-cash-roman-storm-retrial-april-2027-412761
- Samourai: https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-sentenced-five-and-four-years , https://www.irs.gov/compliance/criminal-investigation/founders-of-samourai-wallet-cryptocurrency-mixing-service-sentenced-to-five-and-four-years-in-prison
