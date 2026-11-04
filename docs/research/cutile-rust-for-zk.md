# cuTile Rust for our zk work

Accessed 2026-10-29. All sources were read on that date. **(inference)** marks my own reasoning. **unverified** marks a claim I could not confirm from a primary source.

The question: could NVIDIA's cuTile Rust ([docs](https://nvidia.github.io/cuda-rust/cutile/latest/)) speed up `zk-prover` (Pickles and kimchi over the Pasta curves), or help with anything else zk-related?

## Bottom line

- **cuTile Rust is NVIDIA's tile-based GPU DSL for Rust, and it is built for ML kernels.** You write one program over tiles, and the compiler maps them onto threads, Tensor Cores and TMA. Its tutorials are matmul, softmax, flash attention and FP4 inference. It is an "early-stage research project" that warns of "bugs, incomplete features, and breaking API changes". It runs on stable Rust 1.89 or later, on Linux only, on `sm_80` and newer GPUs, with a CUDA 13.x Tile IR toolchain, and it is Apache-2.0 (sections 1 and 2).
- **It can express 255-bit field arithmetic, but not well.** It has `u32`/`u64` tiles, wrap-around `+`, `-` and `*`, `mulhii` (the high half of an unsigned product), and unsigned compare and select. It has **no add-with-carry, no carry flag, no widening multiply, no `u128`, and no inline PTX or warp-level code inside a tile kernel**. Every carry in a Montgomery multiply would be rebuilt from compares and selects (section 3). **(inference)** That is several times the instruction count of the `add.cc`/`madc` chains that every serious GPU field library uses.
- **The hot parts of our prover are a poor fit for the tile model.** Pippenger MSM is bucket scatter, irregular reductions and point additions with branches. Kimchi's FFTs and quotient evaluation run over 255-bit Pasta elements. Neither looks like the dense, regular tile algebra cuTile is designed for (section 4). **(inference)**
- **Its sibling, cuda-oxide, is the better Rust route to a GPU, if we ever want one.** It lives in the same repository and compiles ordinary per-thread Rust to PTX. It has a `ptx_asm!` macro, which is how you would write carry chains. It is alpha too, and it pins Rust 1.99.1 with `rustc-dev` (section 1).
- **GPU MSM over Pasta already exists, in CUDA C++.** Supranational's `sppark` has a Pasta field (`ff/pasta.hpp`), and its Apache-2.0 `pasta-msm` crate does Pasta MSM on CUDA from Rust. ICICLE does not support Pasta. I found no GPU work for kimchi or Pickles from o1Labs, and nothing that uses cuTile for crypto (section 5).
- **We do not need a GPU prover now.** Our circuits are small (the `land` step is about 1.4k rows, and the largest, the vault's reduce, is about 2^16). The payer proves on its own device, which may have no NVIDIA GPU. At these sizes a GPU's transfer and launch overhead eats most of the gain (section 6). **(inference)**
- **Verdict: not useful for our Pickles prover, and not worth a spike.** If proving time ever becomes the bottleneck on a server, try `pasta-msm`/`sppark` behind kimchi's MSM call first, and only then consider cuda-oxide. cuTile's real zk niche is elsewhere: provers over 31-bit fields (BabyBear, M31) and lattice/FHE NTTs, where its `mmai` int8 Tensor Core path and `mulhii` on `u32` fit well. None of that is our stack (section 7). **(inference)**

## 1. What cuTile Rust is

- **Two kernel models in one project.** NVIDIA's "CUDA Rust" has two models. **cuda-oxide** is "A custom rustc codegen backend… to target the traditional CUDA SIMT… kernel programming model": you write code for one thread, and it compiles ahead of time from Rust to PTX. **cutile-rs** is a proc-macro DSL in which kernels are tile programs, JIT-compiled from Rust through CUDA Tile IR to a cubin ([CUDA Rust overview](https://nvidia.github.io/cuda-rust/)). Both share a runtime (`cuda-bindings`, `cuda-core`, `cuda-async`) ([repo](https://github.com/NVIDIA/cuda-rust)).
- **The tile model.** "Tile kernels are written as single-threaded programs over tiles of data" ([docs home](https://nvidia.github.io/cuda-rust/cutile/latest/)). "Tensors are multi-dimensional arrays in GPU global memory", and "Tiles are immutable multi-dimensional fragments in registers". Each tile block gets one partition of a mutable tensor, so the borrow checker covers the kernel's arguments. Kernels "map onto Tensor Cores, Tensor Memory Accelerator (TMA) instructions" automatically ([introduction](https://nvidia.github.io/cuda-rust/cutile/latest/guide/introduction.html)). Threads, warps and shared memory are not exposed: "thread/warp assignment is compiler-managed" ([interoperability](https://nvidia.github.io/cuda-rust/cutile/latest/guide/interoperability.html)).
- **Target workloads.** The introduction recommends it for "performance-critical ML infrastructure" ([introduction](https://nvidia.github.io/cuda-rust/cutile/latest/guide/introduction.html)). All twelve tutorials are vector or ML kernels: SAXPY, matmul, fused softmax, flash attention, a data-parallel MLP, NVFP4 inference ([docs home](https://nvidia.github.io/cuda-rust/cutile/latest/)).
- **It is the Rust front end to CUDA Tile.** CUDA 13.1 introduced CUDA Tile, a tile model "above SIMT" with two parts: CUDA Tile IR (a virtual ISA) and cuTile Python ([NVIDIA blog, CUDA 13.1](https://developer.nvidia.com/blog/nvidia-cuda-13-1-powers-next-gen-gpu-programming-with-nvidia-cuda-tile-and-performance-gains/)). cuTile Rust emits the same Tile IR ([compatibility](https://nvidia.github.io/cuda-rust/cutile/latest/reference/compatibility.html)).
- **Escape hatches.** A tile kernel can't contain warp-level code or inline assembly. The documented fallback is a separate kernel (cuda-oxide PTX, CUDA C++ PTX or cubin, or Triton) launched through the same runtime. Handles from `cudarc` can be borrowed ([interoperability](https://nvidia.github.io/cuda-rust/cutile/latest/guide/interoperability.html)).

## 2. Maturity, licence, toolchain, hardware

| | cutile-rs | cuda-oxide |
|---|---|---|
| Status | "early stage and under active development… expect bugs, incomplete features, and API breakage" ([cutile-rs](https://github.com/NVIDIA/cuda-rust/tree/main/cutile-rs)) | "early stage (alpha)" ([cuda-oxide README](https://github.com/NVIDIA/cuda-rust/tree/main/cuda-oxide)) |
| Rust | "stable 1.89+ (no nightly required)" | pinned stable 1.99.1, plus `rust-src`, `rustc-dev`, `llvm-tools` |
| CUDA | 13.3 recommended. The `tileiras` assembler fixes the Tile IR version. | Toolkit 13.0+, driver R580+ |
| OS | Linux, tested on Ubuntu 24.04 | Linux, tested on Ubuntu 24.04 |
| GPUs | `sm_80`+. "GPUs below `sm_80` (such as `sm_70` and `sm_75`) are unsupported." | Not stated as a minimum. It emits Hopper and Blackwell intrinsics where asked. |
| Licence | Apache-2.0 | Apache-2.0 |

- **Licence and activity.** "CUDA Rust is licensed under the Apache License 2.0" ([repo](https://github.com/NVIDIA/cuda-rust)). The repository was created 2026-04-22 and last pushed 2026-10-29, and it has no releases (GitHub API, queried 2026-10-29).
- **GPU gates.** Ampere and Ada (`sm_80`–`sm_89`) and Blackwell need Tile IR 13.2. Hopper (`sm_90`) needs 13.3. Some element types and MMA forms are gated per architecture, and "Architecture numbers are not a feature hierarchy" ([compatibility](https://nvidia.github.io/cuda-rust/cutile/latest/reference/compatibility.html)).
- **(inference)** The dev machine's RTX 3080 (GA102, `sm_86`) meets the minimum, so a local experiment would be possible. CI runners and payer devices would not have a GPU.
- **(inference)** Our workspace pins Rust 1.92 (`rust-toolchain.toml`), which satisfies cutile-rs. cuda-oxide would need its own pinned toolchain.

## 3. Can it do 255-bit prime-field arithmetic?

Pallas and Vesta fields are 255-bit primes. A GPU field multiply normally uses 8×32-bit or 4×64-bit limbs, Montgomery reduction, and PTX carry instructions (`add.cc`, `addc`, `mad.lo.cc`, `madc.hi`). That is what `sppark`'s `mont_t.cuh` is built on ([sppark ff/](https://github.com/supranational/sppark/tree/main/ff)). **(inference)**

What cuTile and Tile IR offer:

- **Element types.** `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64`, `bool`, `i4`, plus the float types ([DSL API](https://nvidia.github.io/cuda-rust/cutile/latest/reference/dsl-api.html)). Tile IR's integer types stop at `i64`, and I found no `i128` ([Tile IR operations](https://docs.nvidia.com/cuda/tile-ir/latest/sections/operations.html)).
- **Add, sub, mul wrap.** For `addi`, `subi` and `muli`: "The default semantics are wrap-around semantics on overflow or underflow", and "We store all integers in a two's complement representation". If an op carries an overflow annotation (`NoUnsignedWrap` and so on) and overflows anyway, "the behavior is undefined" ([Tile IR §9.8](https://docs.nvidia.com/cuda/tile-ir/latest/sections/operations.html#integer-arithmetic)).
- **High multiply exists.** "The `mulhii` operation produces the most significant N bits of the 2N-bit product of two N-bit integer tiles… only defined for unsigned integers" ([Tile IR §9.8.10](https://docs.nvidia.com/cuda/tile-ir/latest/sections/operations.html#cuda-tile-mulhii)). The DSL exposes it as `mulhii(a, b)`, and the repo tests it ([integer_ops.rs](https://github.com/NVIDIA/cuda-rust/blob/main/cutile-rs/cutile/tests/integer_ops.rs)).
- **Unsigned compare and select.** `cmpi` takes a `signedness` attribute ([Tile IR §9.8.4](https://docs.nvidia.com/cuda/tile-ir/latest/sections/operations.html#cuda-tile-cmpi)), and the DSL has `lt_tile` and `select` ([DSL API](https://nvidia.github.io/cuda-rust/cutile/latest/reference/dsl-api.html)).
- **No carry chains.** Neither the DSL reference nor the Tile IR operations page mentions add-with-carry, borrow, a carry flag or a widening multiply ([DSL API](https://nvidia.github.io/cuda-rust/cutile/latest/reference/dsl-api.html); [Tile IR operations](https://docs.nvidia.com/cuda/tile-ir/latest/sections/operations.html)). A tile kernel can't fall back to inline PTX ([interoperability](https://nvidia.github.io/cuda-rust/cutile/latest/guide/interoperability.html)).
- **Integer Tensor Cores take 8-bit inputs only.** `mmai` takes `i8` inputs (signed or unsigned per operand) with an `i32` accumulator ([Tile IR §9.8.8](https://docs.nvidia.com/cuda/tile-ir/latest/sections/operations.html#cuda-tile-mmai)).

**(inference)** So a Pasta field multiply in cuTile is possible, with `u64` limbs, `*` plus `mulhii` for the 128-bit partial products, and `sum < a` plus `select` for each carry. That is roughly two to three extra ops per limb step compared with a PTX carry chain. Code generation from Tile IR might fuse some of this, but nothing in the sources says it does (**unverified**). The tile layout would put one limb index on one tile axis, or one field element per tile lane. Both are workable, but nothing in the docs suggests the compiler targets this. The `mmai` int8 path could in principle compute limb products as a matrix multiply, as FHE work does (section 7), but for 255-bit Montgomery products that is research, not engineering.

## 4. Our prover's hot paths, and how they map

What `zk-prover` runs:
- `zk-prover` builds a witness in Rust (`zk-prover/src/witness/`) and proves it with mina-rust's kimchi prover from our pinned fork (ADR 0003, `zk-prover/src/lib.rs`).
- Polynomial commitments are IPA over Pasta. The MSMs go through arkworks `VariableBaseMSM::msm_bigint` in `poly-commitment` (`commitment.rs`, `ipa.rs`, `utils.rs` in proof-systems at our rev).
- `kimchi` and `poly-commitment` parallelise with `rayon` on the CPU (`kimchi/src/prover.rs` and others use it).
- Our own Poseidon in the witness (`witness/gadgets/poseidon.rs`) is a constraint-system mirror, not a bulk hash.

How each hot path maps to tiles:

| Hot path | Shape | Fit for tiles **(inference)** |
|---|---|---|
| MSM (Pippenger, IPA commitments and the opening proof) | Bucket scatter by scalar window, then irregular bucket sums of elliptic-curve point additions, with branches for the identity and doubling | Poor. Scatter and atomics exist (`atomic_rmw_tko`, pointer gather and scatter), but bucket accumulation is the opposite of dense tile algebra. Every point add is about ten 255-bit multiplies without carry chains. |
| FFT / NTT over Pasta fields | Butterfly passes with strided access | Moderate on shape (strided views exist), poor on arithmetic (255-bit) |
| Quotient and expression evaluation over the d8 domain | Element-wise over large vectors | Best shape match (element-wise tile ops), still 255-bit arithmetic |
| Poseidon (kimchi: width 3, x^7 S-box, 55 rounds) | Many independent hashes if batched | Batch shape fits tiles. The per-element arithmetic is the problem again. |
| Witness generation | Sequential gadget mirrors, about 18k values for `land` | Not parallel work. No fit. |

The workspace notes give the scale: "zk-prover builds an 18k-value witness and proves a 1.4k-row circuit" (`Cargo.toml`). A vault reduce is "near 2^16 rows" and adds "minutes per transaction" when proved inside o1js's test gate (`docs/verification-keys.md`). Pickles fixes the domain sizes of its recursive (wrap) circuits; I did not check the exact sizes (**unverified**).

## 5. Existing GPU zk work that bears on Pasta

- **sppark (Supranational)** is a "Zero-knowledge template library" in CUDA C++. It has a Pasta field (`ff/pasta.hpp`) on its Montgomery template (`mont_t.cuh`), plus BLS12-377/381, BN254, Goldilocks, BabyBear and Mersenne-31 fields ([repo](https://github.com/supranational/sppark), [ff/](https://github.com/supranational/sppark/tree/main/ff)). It is Apache-2.0 and was last pushed 2026-10-20 (GitHub API).
- **pasta-msm (Supranational)** offers "Optimized multiscalar multiplicaton for Pasta moduli for x86_64 and aarch64". It is a Rust crate that depends on `sppark` and `pasta_curves` and has a `cuda` directory ([repo](https://github.com/supranational/pasta-msm), [Cargo.toml](https://github.com/supranational/pasta-msm/blob/main/Cargo.toml)). The README calls it an "initial version" and warns that the CUDA path "doesn't yet adapt to the actual workload". It is Apache-2.0 and was last pushed 2025-09-06.
  - **(inference)** It takes zcash `pasta_curves` types, not arkworks `mina-curves`, so using it from kimchi would need a conversion layer and a patch to `poly-commitment`'s MSM call in our fork.
- **ICICLE (Ingonyama)** supports BN254, BLS12-377, BLS12-381, BW6-761 and Grumpkin, and no Pasta (`icicle/include/icicle/curves/params`, [repo](https://github.com/ingonyama-zk/icicle)). Its frontend is MIT. Its CUDA backend "[is] distributed under a special license" ([README](https://github.com/ingonyama-zk/icicle#license)).
- **o1Labs.** The only CUDA code I found in the o1-labs org is `libsnark-ocaml`'s `cuda_prover`, which predates Pickles. I found nothing for kimchi or Pickles (GitHub code search over `o1-labs` for "cuda" and "gpu msm"). That absence is **unverified**, since search only covers indexed code.
- **Research.** GPU work has concentrated on MSM, and NTT kernels remain under-optimised ([ZKProphet, arXiv 2509.22684](https://arxiv.org/abs/2509.22684)). cuZK reports 2.08× to 2.94× over the previous best GPU MSM ([eprint 2022/1321](https://eprint.iacr.org/2022/1321)). Neither uses a tile DSL.
- **cuTile for crypto.** GitHub searches for cuTile or `cuda_tile` together with MSM, NTT or Montgomery found nothing (2026-10-29).

## 6. Does it fit our deployment?

- **Who proves.** The payer wallet does its own proving ("Rust, with o1js only for proving", `docs/design/zkapi-payments.md`). The transaction builder proves vault transactions and request proofs for Rust callers (GLOSSARY, *Transaction builder*). The connector proves its zkApp transactions in Rust with `zk-prover` (ADR 0003). The zk edge and the challenger mostly **verify** (`zk-prover/src/verify.rs`).
- **Payer devices.** cuTile needs Linux, an NVIDIA `sm_80`+ GPU and a CUDA 13 driver (section 2). That rules out phones, Macs and most laptops. **(inference)** A GPU path could only ever be optional on the payer side.
- **Server side.** A zk edge operator or connector could rent a GPU. **(inference)** Proving is not where our latency goes, though. The design already avoids proving per packet ("each proof costs seconds", `docs/design/zkapi-payments.md`). Allowances amortise one proof over many packets, and vault transactions are rare and asynchronous (reduce, close, escape).
- **Size.** At around 2^11 to 2^16 rows, the MSMs and FFTs are small. **(inference)** Host-to-device copies, kernel launches and (for cuTile) JIT compilation on first use take a large share of the gain at these sizes. Published GPU MSM wins are usually reported at 2^20 and above (**unverified** as a general threshold; the cuZK and ZKProphet papers benchmark large sizes).
- **Cost of the dependency.** A GPU path would add the CUDA toolkit and `tileiras` to builds, a second code path in the vendored prover, and GPU runners for the gate. A crate warning of "API breakage" would sit under money-moving code. **(inference)**

## 7. Where cuTile could matter in zk, including novel uses

All of the following is **(inference)** unless cited.

- **Small-field provers (BabyBear, Mersenne-31, Goldilocks).** One element fits in a `u32` or `u64`, so `muli` plus `mulhii` is a complete multiply. NTTs and Poseidon2 over these fields are dense, batched and regular, which is what tiles are for. This is the most credible zk use of cuTile. It is not our stack: Pickles is over Pasta.
- **Lattice and FHE NTTs on Tensor Cores.** TensorFHE splits 32-bit words into 8-bit pieces so that NTTs run on Tensor Cores, and reports about 2.61× over earlier GPU work on an A100 ([arXiv 2212.14191](https://arxiv.org/abs/2212.14191)). FHECore notes that this splitting adds overhead ([arXiv 2602.22229](https://arxiv.org/abs/2602.22229)). cuTile's `mmai` (int8 to int32) is the matching primitive, and writing that in safe Rust would be new. It is relevant to us only if we ever add FHE or lattice-based privacy, which nothing in our design plans.
- **zkML witness generation.** The forward pass of a quantised model, whose trace a zkML circuit then proves, is exactly cuTile's workload. We have no zkML.
- **Batch Poseidon over Pasta (Merkle rebuilds, nullifier-set indexing).** This would work as a large element-wise batch with the carry overhead of section 3. Our trees change once per vault action, and the challenger reads the chain rather than rebuilding large trees. There's no throughput problem to solve.
- **Batch verification for a busy zk edge.** IPA verification ends in one large MSM per proof, and `poly-commitment` can batch several proofs into one. A zk edge receiving thousands of request proofs a second might batch them onto a GPU. That is the MSM problem again, so `sppark` would be the tool, not cuTile. At today's volumes, CPU verification is fine.

## 8. Recommendation

1. Don't adopt cuTile Rust for `zk-prover`. It lacks carry arithmetic and low-level control, and it is research-stage.
2. Don't open a GPU issue now. Record proving times for the real circuits first (request proof, close, reduce) on the payer's and the operator's hardware. Today the repo has only "seconds" and "minutes".
3. If server proving time ever matters, profile kimchi first (MSM against FFT against quotient evaluation). Then try `pasta-msm`/`sppark` behind `poly-commitment`'s MSM in our fork, with a conversion between arkworks and `pasta_curves`. Consider cuda-oxide with `ptx_asm!` carry chains only if a pure-Rust GPU path becomes a goal of its own.
4. Revisit cuTile if we adopt a small-field proof system or lattice/FHE primitives, or if NVIDIA adds carry or wide-integer ops to Tile IR.

## Sources

- cuTile Rust docs: https://nvidia.github.io/cuda-rust/cutile/latest/ ; introduction: https://nvidia.github.io/cuda-rust/cutile/latest/guide/introduction.html ; tensors and tiles: https://nvidia.github.io/cuda-rust/cutile/latest/guide/tensors-and-tiles.html ; interoperability: https://nvidia.github.io/cuda-rust/cutile/latest/guide/interoperability.html ; DSL API: https://nvidia.github.io/cuda-rust/cutile/latest/reference/dsl-api.html ; compatibility: https://nvidia.github.io/cuda-rust/cutile/latest/reference/compatibility.html
- CUDA Rust overview: https://nvidia.github.io/cuda-rust/ ; repo: https://github.com/NVIDIA/cuda-rust ; cutile-rs: https://github.com/NVIDIA/cuda-rust/tree/main/cutile-rs ; cuda-oxide: https://github.com/NVIDIA/cuda-rust/tree/main/cuda-oxide ; inline PTX example: https://github.com/NVIDIA/cuda-rust/tree/main/cuda-oxide/crates/rustc-codegen-cuda/examples/inline_ptx
- CUDA Tile IR operations: https://docs.nvidia.com/cuda/tile-ir/latest/sections/operations.html
- CUDA 13.1 and CUDA Tile: https://developer.nvidia.com/blog/nvidia-cuda-13-1-powers-next-gen-gpu-programming-with-nvidia-cuda-tile-and-performance-gains/
- sppark: https://github.com/supranational/sppark ; pasta-msm: https://github.com/supranational/pasta-msm
- ICICLE: https://github.com/ingonyama-zk/icicle
- o1Labs libsnark-ocaml (pre-Pickles CUDA prover): https://github.com/o1-labs/libsnark-ocaml
- ZKProphet: https://arxiv.org/abs/2509.22684 ; cuZK: https://eprint.iacr.org/2022/1321 ; TensorFHE: https://arxiv.org/abs/2212.14191 ; FHECore: https://arxiv.org/abs/2602.22229
