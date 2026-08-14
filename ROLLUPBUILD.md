# ZK-Rollup extension for `rippled`

This repository is a fork of [XRPL's `rippled`](https://github.com/XRPLF/rippled) that adds a
zero-knowledge rollup to the ledger: batches of off-chain state transitions are settled on-chain by
verifying a succinct proof instead of re-executing every transaction. This file covers only what the
fork adds — where that code lives, how to build it, and how to run it. [`README.md`](README.md) is
upstream's, and [`BUILD.md`](BUILD.md) has the general `rippled` build instructions.

## What this fork adds

Three rollup designs share one codebase so they can be compared on equal terms. All three are
Groth16 over BN-254 (libsnark), with Poseidon (t=3, R_F=8, R_P=57, x^5 S-box) as the in-circuit hash
and Baby Jubjub / EdDSA-Poseidon for in-circuit signatures.

| | Transaction | Amendment | Proof model | Who proves |
|:--|:--|:--|:--|:--|
| **Track 1** | `BatchRollup` (tt=61) | `ZKRollup` | N independent per-entry proofs, each verified separately | each user, locally |
| **Track 2** | `BatchRollup2` (tt=62), `RollupDeposit2` (tt=63) | `ZKRollup2` | one proof for the whole batch | the sequencer |
| **Track 3** | `BatchRollupAgg` (tt=64) | `ZKRollupAgg` | Track 1's N proofs aggregated into one, verified in O(log N) pairings | each user, locally; the sequencer only aggregates |

Track 3 is not a separate rollup — it is an alternative proof-verification path over the same
`RollupState` tree as Track 1, so a batch can be settled either way.

The rollup state lives in new ledger entries reached through `keylet::rollup_state()` (Tracks 1 and
3) and `keylet::rollup_state2()` (Track 2 and its deposits). Each track's proof blob travels in the
`sfBatchProof` field; at N=8 that is 2420 B for Track 1 and 1085 B for Track 2.

## Where the code is

| Path | Contents |
|:--|:--|
| `src/libxrpl/zkp/rollup/` | the whole rollup: circuits, gadgets, provers, sequencers, on-chain verifiers |
| `src/test/zkp/rollup/` | unit tests for every component above |
| `src/tools/` | standalone blob generators and benchmarks |
| `tools/phase5/`, `tools/phase6/` | end-to-end and head-to-head demo scripts |
| `include/xrpl/protocol/detail/*.macro` | new transaction types, ledger entries, fields and amendments |
| `src/libxrpl/zkp/` (outside `rollup/`) | an earlier shielded-pool layer that predates the rollup |

Starting points inside `src/libxrpl/zkp/rollup/`:

- `PoseidonCircuit.h` — Track 1's per-note circuit (5 public inputs, one Merkle path).
- `BatchCircuit.h` — Track 2's batch circuit; `BatchProof2.h` documents its wire format byte by byte.
- `ProofAggregator.h` — Track 3's SnarkPack-style aggregation (merged TIPP/MIPP GIPA, KZG final-key
  openings).
- `BatchVerifier.h`, `BatchVerifier2.h`, `BatchVerifierAgg.h` — the `preflight`/`preclaim`/`doApply`
  logic for tt=61/62/64.
- `RollupSequencer.h`, `RollupSequencer2.h` — the off-chain batch builders.

## Building

Standard `rippled` build; see [`BUILD.md`](BUILD.md) for prerequisites (Conan 2, CMake, a C++20
compiler — this was built with GCC 13 on Ubuntu 22.04). No extra flags are needed: the rollup
sources are part of `xrpl.libxrpl`, and `external/libsnark` is vendored in-tree.

```bash
mkdir -p build/main && cd build/main
conan install ../.. --output-folder . --build missing --settings build_type=Release
cmake -DCMAKE_TOOLCHAIN_FILE:FILEPATH=generators/conan_toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release -Dxrpld=ON -Dtests=ON ../..
cmake --build . -j$(nproc)
```

A full build takes a while; `cmake --build . --target xrpl.libxrpl` builds the rollup library alone.

## Running the tests

The rollup suites live under the `zkp`, `zkp_rollup` and `rollup` groups:

```bash
./rippled --unittest=PoseidonCircuit     # per-note circuit, Track 1
./rippled --unittest=BatchCircuit        # batch circuit, Track 2
./rippled --unittest=BatchVerifier       # on-chain verification path
./rippled --unittest=RollupMerkleTree    # tree and auth paths
./rippled --unittest=zkp                 # everything in the zkp group
```

Suites that generate real proofs are marked manual (`RollupProver`, `BatchCircuitProver`,
`BatchVerifier2`, `RollupSequencer2`, `RollupBench`) because a single Groth16 setup plus proof runs
into minutes, so a group name like `--unittest=zkp` skips them. Naming a manual suite exactly runs
it:

```bash
./rippled --unittest=RollupProver
```

Proving and verification keys are generated on first use and cached under `/tmp/rippled_rollup_keys`
(Track 1), `/tmp/rippled_rollup_batch_keys` (Track 2) and `/tmp/rippled_rollup_agg_srs` (Track 3's
aggregation SRS) — three independent setups, deliberately never sharing a file. The
first run of any proving test therefore pays a one-off setup cost, and deleting those files forces a
fresh setup.

## Tools and benchmarks

Built alongside `rippled` whenever `-Dxrpld=ON`:

- `gen_batch_blob`, `gen_batch_blob2`, `gen_batch_blob_agg` — produce a valid `sfBatchProof` blob for
  Track 1, 2 and 3 respectively, for submitting real transactions to a standalone node.
- `bench_proof_aggregator` — Track 3 aggregation and verification timings.
- `bench_track2_scale` — Track 2 at batch sizes other than N=8.


## Status and limitations

This is a research prototype, not production code.

- Each proving system uses a locally generated trusted setup (the toxic waste is sampled and
  discarded in-process). A real deployment would need an MPC ceremony.
- Batch size N is fixed at 8 in the default configuration; Track 3 requires N to be a power of two.
- Amounts are public by design — the threat model is integrity, not confidentiality.
- The sequencer is a single trusted-for-liveness party; it cannot steal funds, but it can stall.

## License

Upstream `rippled` is ISC licensed; see [`LICENSE.md`](LICENSE.md). The rollup code added in this
fork is released under the same terms.
