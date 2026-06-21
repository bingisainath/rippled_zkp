# Lever #3 evaluated: Poseidon2 — negative result for Groth16/R1CS

**Date:** 2026-06-19
**Decision:** Evaluated and *not* adopted. Documented here as a negative result.

## Summary

Poseidon2 (Grassi, Khovratovich, Schofnegger — ePrint 2023/323) was evaluated as
the next proving-time optimization after Lever #1 (single Merkle path) and
Lever #2 (tree depth 32→16). **It was rejected because it yields essentially zero
reduction in proving time in our Groth16 / libsnark R1CS backend**, while
requiring a high-risk rewrite of both the in-circuit gadget and the off-circuit
hash reference (which must remain bit-identical, or every Merkle root and
nullifier in the system breaks).

## Where our proving cost actually comes from

Reading `src/libxrpl/zkp/rollup/PoseidonGadget.cpp`, the per-permutation cost in
an R1CS / Groth16 circuit decomposes as:

| Component                  | Multiplicative R1CS constraints |
|----------------------------|---------------------------------|
| S-box `x → x⁵` per lane    | 3  (x²=x·x, x⁴=x²·x², x⁵=x⁴·x)  |
| MDS / linear mix layer     | 0  (linear combinations are free) |
| Round-constant addition    | 0  (linear)                     |

Per Poseidon-π permutation (t=3, R_F=8 full rounds, R_P=57 partial rounds):

```
8 full rounds   × 3 lanes × 3 = 72
57 partial      × 1 lane  × 3 = 171
                       total  = 243 multiplicative constraints
```

**The constraint count is 100% S-boxes.** The mixing matrix contributes nothing,
because in R1CS a linear map is absorbed into the A/B/C linear forms of
neighbouring constraints at zero multiplicative cost.

## What Poseidon2 changes — and why it doesn't help us

Poseidon2 keeps:
- the **same S-box** (`x⁵` on BN254),
- the **same round numbers** (R_F = 8, R_P ≈ 57 for 128-bit security, t=3).

Poseidon2's improvement is a **cheaper linear layer**: a sparse internal matrix
`M_I = J + diag(d_i)` for partial rounds and an efficient external matrix `M_E`
for full rounds. This reduces the number of *field multiplications in the linear
layer*, which dominates:
- **native / plain-software hashing** (fewer mults per permutation), and
- **Plonkish / AIR backends** (Plonky2, Halo2) where the linear layer costs gates.

But in **Groth16 / R1CS the linear layer is already free**. Since Poseidon2 does
not change the S-box or the round counts, its **multiplicative constraint count is
identical to Poseidon's: 243 per permutation**. Our circuit would stay at
**16581 constraints** and proving time at **~3.92 s** — no measurable change.

This matches the Poseidon2 paper's own benchmarks: the headline speedups are for
Plonky2 / native, and are negligible for Groth16.

## Correction to an earlier characterisation

An earlier note described Poseidon2 as cutting constraints via "fewer full-round
MDS multiplications." That is true for **native and Plonkish** arithmetizations,
but **not for our R1CS Groth16 path**, where MDS multiplications are free. The
corrected conclusion is the one above: no Groth16 benefit.

## What *does* reduce Groth16 proving time here

Because cost = (number of Poseidon invocations) × 243 S-box gates, the only
effective levers reduce the *number of invocations*, not the cost per call:

1. **Lever #2 (already landed):** depth 32→16 halved the Merkle path's Poseidon
   calls → 23701→16581 constraints, 5.42 s→3.92 s. This is exactly why it worked.
2. **Further depth reduction** (16→12→…): cuts more, trading leaf capacity
   (2¹⁶ = 65 536 → 2¹² = 4 096). A *depth-vs-latency Pareto curve* is the honest
   way to present this rather than silently picking the smallest depth.
3. **Proof aggregation / recursion:** reduces on-chain *verification* cost
   (8 verifies → 1), not prover time.

## Verdict

Poseidon2 is the right optimization for a Plonkish or native target; it is the
wrong optimization for this Groth16/R1CS rollup. Adopting it would risk the
working depth-16 system (all roots, nullifiers and Groth16 keys would have to be
regenerated and re-validated) for no measurable proving-time gain. Recommended
next real lever: a depth-vs-latency tradeoff curve.
