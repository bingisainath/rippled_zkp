# Benchmark Summary

Elapsed times in microseconds, aggregated over successful runs only. `proof_bytes` is the per-proof or per-batch Groth16 byte count; `tx_bytes` is the serialised STTx size; `fee_drops` is the ledger-recorded fee.

## Per-scenario aggregates

| scenario             |   runs |   elapsed_us_mean |   elapsed_us_std |   elapsed_us_min |   elapsed_us_max |   proof_bytes_mean |   tx_bytes_mean |   fee_drops_mean |
|:---------------------|-------:|------------------:|-----------------:|-----------------:|-----------------:|-------------------:|----------------:|-----------------:|
| baseline_payment_x8  |      5 |   13587.2         |         3815.86  |  10505           |  19404           |                  0 |          1459.6 |               80 |
| onchain_pipeline_n8  |      5 |   19297.8         |         6500.45  |   7765           |  23123           |               1536 |             0   |                0 |
| prover_createProof   |      5 |       4.93848e+06 |        40578.2   |      4.89724e+06 |      4.99753e+06 |                137 |             0   |                0 |
| verifier_verifyProof |      5 |    5844           |          103.143 |   5740           |   6007           |                137 |             0   |                0 |

## Headline numbers

- **Per-proof generation (mean):** 4938.5 ms
- **Per-proof verification (mean):** 5.8 ms
- **On-chain pipeline, N=8 (mean):** 19.3 ms
- **Baseline 8x Payment (mean):** 13.6 ms