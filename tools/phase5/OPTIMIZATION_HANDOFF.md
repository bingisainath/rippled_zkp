# ZK-Rollup on XRPL — Optimization Work Handoff

> **How to use this file:** Paste the "PROMPT FOR CLAUDE" block below into a Claude
> session that has access to this repo. It will then explain every change in depth,
> file by file. The rest of the document is the summary + before/after comparison.

---

## PROMPT FOR CLAUDE (copy this)

> I have an MSc dissertation project: a ZK-Rollup extension on the XRP Ledger
> (a fork of rippled). You have access to the repo. I optimized the L2 proof
> generation latency from ~8.1s to ~3.9s per proof **without any hardware
> changes (no GPU, no extra cores)** — purely through circuit/protocol design.
>
> Explain to me **in depth, with code references**, exactly what was done. Cover:
> 1. The architecture: BatchRollup transactor, Groth16 (libsnark r1cs_gg_ppzksnark,
>    BN254), the PoseidonCircuit, RollupMerkleTree, RollupSequencer, BatchVerifier.
> 2. **Lever #1 — single Merkle path.** Read `PoseidonCircuit.cpp` and
>    `RollupProver.cpp`. Explain how the second in-circuit Merkle path was removed,
>    why it was safe (the new root is enforced off-circuit by doApply's root-replay
>    in `BatchVerifier.cpp`), what `new_cm` as the 2nd public input means, and the
>    constraint/time impact.
> 3. **Lever #2 — tree depth 32→16.** Read `RollupState.h`, `RollupMerkleTree.h`,
>    `RollupProver.h/.cpp`, `RollupSequencer.cpp`. Explain why halving depth halves
>    the Merkle path's Poseidon calls, the capacity tradeoff (2^32 → 2^16 leaves),
>    and how the genesis root recomputes.
> 4. **Lever #3 — Poseidon2, evaluated and REJECTED.** Read
>    `tools/phase5/poseidon2_evaluation.md`, `PoseidonGadget.cpp`. Explain WHY
>    Poseidon2 gives no Groth16 benefit (R1CS constraint count is 100% S-boxes;
>    the linear/MDS layer is free in R1CS; Poseidon2 only speeds up the linear
>    layer which matters for native/Plonkish backends, not Groth16).
> 5. The benchmark methodology: `src/test/zkp/rollup/RollupBench_test.cpp`
>    (in-process per-phase timing + Merkle write-amplification) and
>    `tools/phase5/bench_live_e2e.sh` (live standalone node, real tesSUCCESS flow).
> 6. How correctness was preserved: 11-scenario demo (31 assertions),
>    full `rippled --unittest`, and the field round-trip invariant
>    (`PoseidonHash::uint256ToField ∘ fieldToUint256 == id`).
>
> Walk me through each lever as if teaching me, quoting the actual code.

---

## What we built (summary)

A ZK-Rollup that batches **8 private transfers** into **one** XRPL L1 transaction
(`BatchRollup`). Each transfer carries a Groth16 proof over a Poseidon-based
circuit proving Merkle membership + a valid state transition. The on-chain
transactor verifies all 8 proofs in `preclaim` and replays the Merkle updates in
`doApply`, advancing a single on-chain root.

### The optimization goal
Reduce L2 proof-generation latency (the dominant cost: ~8s/proof × 8 = ~65s/batch)
toward native-transaction latency, **without hardware** (personal VM, no GPU).

### What we changed (3 levers)

**Lever #1 — Single Merkle path (circuit redesign).**
The circuit originally proved *two* Merkle paths: the old leaf's membership in the
old root, and the new leaf's membership in the new root. But `doApply` already
re-inserts each commitment off-circuit and asserts the result equals the claimed
new root (`BatchVerifier.cpp` root-replay). So the second in-circuit path was
*redundant* — it only bound the private new commitment to the new root. We removed
it and instead exposed the new commitment (`new_cm`) as a public input, letting the
off-circuit replay carry the new-root check.
*Result: 37911 → 23701 constraints; 8.12s → 5.42s; new root bit-identical.*

**Lever #2 — Tree depth 32 → 16.**
Merkle membership cost scales with tree depth (one Poseidon hash per level).
Halving the depth halves the Poseidon calls in the membership gadget. Capacity
drops from 2^32 to 2^16 = 65,536 leaves — ample for a prototype/demo. The genesis
root recomputes at the new depth; the demo and live harness fetch it dynamically.
*Result: 23701 → 16581 constraints; 5.42s → 3.92s. Target (3–4s) hit.*

**Lever #3 — Poseidon2: evaluated, REJECTED.**
In a Groth16/R1CS circuit the constraint count is 100% S-boxes (x→x⁵ = 3 mul gates
per lane). The MDS/linear mix layer is *free* in R1CS. Poseidon2 only makes the
linear layer cheaper — a win for native hashing and Plonkish backends (Plonky2/
Halo2), but **zero benefit for Groth16**. Documented as a negative result; not
implemented. See `poseidon2_evaluation.md`.

### What we did NOT touch
Lin et al's pre-existing privacy transactor (ZkDeposit / ZkWithdraw / ZkProver) —
left completely untouched.

---

## Before vs Current (small comparison)


| Metric                         | Before (original) | Current (landed)        | Change |
|--------------------------------|-------------------|-------------------------|--------|
| Circuit Merkle paths in-circuit | 2 (old + new)     | 1 (old only)            | −1 path |
| Merkle tree depth              | 32                | 16                      | −half |
| **R1CS constraints**           | **37,911**        | **16,581**              | **−56%** |
| **Proving time / proof**       | **~8.12 s**       | **~3.92 s**             | **−52% (≈2.1× faster)** |
| Proving time / 8-proof batch   | ~64.8 s           | ~31.1 s                 | −52% |
| Tree capacity (leaves)         | 2³² ≈ 4.3 B       | 2¹⁶ = 65,536            | smaller (fine for demo) |
| On-chain submit / ledger close | ~327 ms / ~188 ms | unchanged               | no regression |
| New Merkle root (correctness)  | baseline          | bit-identical           | preserved |
| Hardware used                  | none              | none                    | no GPU / no extra cores |

**Headline:** ~2.1× faster proving and 56% fewer constraints, achieved purely by
circuit/protocol design — no hardware. Correctness preserved: 11-scenario demo
(31 assertions) passes, full unit suite passes (only the pre-existing, unrelated
`MPToken_test.cpp:1853` failure remains).

### Why these specifically (and why not more)
Proving cost = (number of Poseidon invocations) × 243 S-box gates each. So the only
effective levers *reduce the number of Poseidon calls*: Lever #1 dropped a whole
path, Lever #2 halved the path length. Poseidon2 was rejected because it changes
the *per-call linear layer cost*, which is free in R1CS. The only remaining
prover-time lever is further depth reduction (a capacity tradeoff, best shown as a
depth-vs-latency curve). Aggregation/recursion would cut on-chain verify cost (not
prover time); a nullifier accumulator would cut space (not time).
