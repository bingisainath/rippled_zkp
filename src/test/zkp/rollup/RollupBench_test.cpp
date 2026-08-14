// RollupBench_test.cpp — benchmark suite.
//
// Scope:
//   1. Measure RollupProver::createProof wall-clock latency over N runs.
//   2. Measure RollupProver::verifyProof wall-clock latency over N runs.
//   3. Measure the existing BatchVerifier preflight+preclaim pipeline
//      end-to-end via the tampered-rejection path (the only currently-
//      reachable real-proof on-chain path).
//   4. Measure 8x stock XRPL Payment as a baseline for fee/byte/latency
//      amortisation comparison.
//   5. Emit one CSV row per measurement run for the dissertation
//      evaluation chapter's tables and figures.
//
// What this suite does NOT do:
//   - Does not chase tesSUCCESS for a real-proof batch: that requires
//     API changes
//     (per-entry prev_root reconciliation between createProof and
//     verifyEntry) that are out of scope for an evaluation deliverable.
//   - Does not introduce new production code on the consensus hot path.
//     Every symbol referenced here is already exported.
//
// Run:
//     export ROLLUP_BENCH_CSV=/tmp/rollup_bench.csv
//     export ROLLUP_BENCH_RUNS=5
//     ./rippled --unittest=ripple.zkp_rollup.RollupBench

#include <libxrpl/zkp/circuits/MerkleCircuit.h>
#include <libxrpl/zkp/rollup/BatchProof.h>
#include <libxrpl/zkp/rollup/PoseidonHash.h>
#include <libxrpl/zkp/rollup/RollupKeylets.h>
#include <libxrpl/zkp/rollup/RollupMerkleTree.h>
#include <libxrpl/zkp/rollup/RollupNote.h>
#include <libxrpl/zkp/rollup/RollupProver.h>
#include <libxrpl/zkp/rollup/RollupState.h>

#include <test/jtx.h>
#include <test/jtx/Env.h>

#include <xrpl/basics/StringUtilities.h>
#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/jss.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace ripple {
namespace test {

using zkp::rollup::BatchProof;
using zkp::rollup::BATCH_SIZE;
using zkp::rollup::FieldT;
using zkp::rollup::kRollupTreeDepth;
using zkp::rollup::PoseidonHash;
using zkp::rollup::RollupNote;
using zkp::rollup::RollupProver;
using zkp::rollup::RollupProofData;
using zkp::rollup::RollupTxEntry;
using zkp::rollup::RollupTxType;
using zkp::rollup::SEQUENCER_SIG_BYTES;

// Bench infrastructure

// Wall-clock stopwatch. steady_clock is the only correct choice on a shared
// VM, since NTP can step system_clock backwards during a run.
class Stopwatch
{
public:
    Stopwatch() : start_(clock::now()) {}

    void
    restart() noexcept
    {
        start_ = clock::now();
    }

    std::int64_t
    elapsedUs() const noexcept
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   clock::now() - start_)
            .count();
    }

private:
    using clock = std::chrono::steady_clock;
    clock::time_point start_;
};

// One CSV row. Sparse — fields not relevant to a given scenario stay zero.
//
// Per-stage L2->L1 decomposition and Merkle-tree work:
//   `phase`          sub-stage label within a scenario ("witness",
//                    "createProof", "serialize", "sign", "total", ...);
//                    empty for the original coarse-grained scenarios.
//   `nL2Txs`         number of L2 transitions this row accounts for (8 for a
//                    full batch) — lets the analyser amortise to per-L2-tx.
//   `merkleUpdates`  number of leaf mutations (append/update_leaf).
//   `poseidonHashes` number of Poseidon(L,R) evaluations implied (depth * N).
//   `rootWrites`     on-chain Merkle-root writes (1 for a rollup batch,
//                    N for N independent L1 transactions).
//   `stateWrites`    on-chain SLE/AccountRoot writes (the L1 footprint).
struct BenchRow
{
    std::string scenario;
    std::uint32_t run = 0;
    std::string phase;
    std::int64_t elapsedUs = 0;
    std::size_t proofBytes = 0;
    std::size_t txBytes = 0;
    std::int64_t feeDrops = 0;
    std::uint32_t nL2Txs = 0;
    std::uint64_t merkleUpdates = 0;
    std::uint64_t poseidonHashes = 0;
    std::uint32_t rootWrites = 0;
    std::uint32_t stateWrites = 0;
    std::string outcome;
};

// Thread-safe CSV sink. Header is written on first call to writeHeader().
class CsvSink
{
public:
    explicit CsvSink(std::string path) : path_(std::move(path)) {}

    void
    writeHeader()
    {
        std::lock_guard lock(mu_);
        if (headerWritten_)
            return;
        // A fresh CsvSink is constructed per test case, so the in-memory
        // flag alone would re-emit the header for every scenario. Suppress
        // it when the file already has content (header written by an earlier
        // sink, or rows appended by the live harness).
        {
            std::ifstream in(path_, std::ios::ate | std::ios::binary);
            if (in.good() && in.tellg() > 0)
            {
                headerWritten_ = true;
                return;
            }
        }
        std::ofstream out(path_, std::ios::out | std::ios::app);
        // The schema carries `phase` and the Merkle-work
        // columns. The columns are appended after the original ones so the
        // analyser's subset-based column check stays backward-compatible.
        out << "scenario,run,phase,elapsed_us,proof_bytes,tx_bytes,fee_drops,"
               "n_l2_txs,merkle_updates,poseidon_hashes,root_writes,"
               "state_writes,outcome\n";
        headerWritten_ = true;
    }

    void
    append(BenchRow const& r)
    {
        std::lock_guard lock(mu_);
        std::ofstream out(path_, std::ios::out | std::ios::app);
        out << r.scenario << ',' << r.run << ',' << r.phase << ','
            << r.elapsedUs << ',' << r.proofBytes << ',' << r.txBytes << ','
            << r.feeDrops << ',' << r.nL2Txs << ',' << r.merkleUpdates << ','
            << r.poseidonHashes << ',' << r.rootWrites << ',' << r.stateWrites
            << ',' << r.outcome << '\n';
    }

private:
    std::mutex mu_;
    std::string path_;
    bool headerWritten_ = false;
};

// Witness builder — synthetic Lin-style state transition.
//
// This is the SAME recipe used by BatchVerifier_test::makeRealSignedBatch
// and PoseidonCircuit_test. All eight authentication
// path siblings are the empty-tree hash chain rooted at PoseidonHash::
// zeroZero(). The "old note" has value=0 (synthetic spend-from-nothing),
// the "new note" inherits old's ask/apk so the nullifier ties to a fresh
// nf = Poseidon(ask, rho_old).

struct HonestWitness
{
    RollupNote old_note;
    RollupNote new_note;
    std::vector<bool> leaf_pos;
    std::vector<FieldT> auth_path_old;
    std::vector<FieldT> auth_path_new;
    FieldT prev_root;
    FieldT new_root;
};

static HonestWitness
buildHonestWitness(std::uint64_t seedOld, std::uint64_t seedNew,
                   std::uint64_t value)
{
    HonestWitness w;
    w.old_note = RollupNote::createRandom(/*value=*/0, seedOld);
    w.new_note = RollupNote::createRandom(value, seedNew);
    w.new_note.ask = w.old_note.ask;
    w.new_note.apk = w.old_note.apk;

    w.leaf_pos.assign(kRollupTreeDepth, false);
    w.auth_path_old.reserve(kRollupTreeDepth);

    FieldT cur = PoseidonHash::zeroZero();
    w.auth_path_old.push_back(FieldT::zero());
    for (std::size_t lvl = 1; lvl < kRollupTreeDepth; ++lvl)
    {
        w.auth_path_old.push_back(cur);
        cur = PoseidonHash::hash(cur, cur);
    }
    w.auth_path_new = w.auth_path_old;

    auto rootFromLeaf = [&w](FieldT const& leaf) {
        FieldT acc = leaf;
        for (std::size_t lvl = 0; lvl < kRollupTreeDepth; ++lvl)
            acc = PoseidonHash::hash(acc, w.auth_path_old[lvl]);
        return acc;
    };
    w.prev_root = rootFromLeaf(w.old_note.commitment());
    w.new_root  = rootFromLeaf(w.new_note.commitment());
    return w;
}

// The test suite

class RollupBench_test : public beast::unit_test::suite
{
    // Configuration via environment variables — same convention as the
    // existing rippled benchmark suites.
    static std::string
    csvPath()
    {
        if (auto const env = std::getenv("ROLLUP_BENCH_CSV"); env)
            return env;
        return "/tmp/rollup_bench.csv";
    }

    static std::uint32_t
    numRuns()
    {
        if (auto const env = std::getenv("ROLLUP_BENCH_RUNS"); env)
        {
            auto const n = std::atoi(env);
            return n > 0 ? static_cast<std::uint32_t>(n) : 1u;
        }
        return 3u;
    }

    // Test cases

    // Bench 1: per-proof generation cost (client-side, off the consensus
    // path). Design budget: ~3–5 s per proof at depth=32.
    void
    testProverLatency()
    {
        testcase("RollupProver::createProof latency");

        // First call may take 30–60s for trusted setup. The
        // BatchVerifier suite already initialises in its `run()`; this
        // is idempotent.
        RollupProver::initialize();

        CsvSink sink(csvPath());
        sink.writeHeader();

        auto const runs = numRuns();
        for (std::uint32_t i = 0; i < runs; ++i)
        {
            auto const w = buildHonestWitness(
                /*seedOld=*/0xC300 + i,
                /*seedNew=*/0xD400 + i,
                /*value=*/1'000'000ULL * (i + 1));

            Stopwatch t;
            auto const pd = RollupProver::createProof(
                w.old_note, w.new_note, w.leaf_pos,
                w.auth_path_old, w.auth_path_new,
                w.prev_root, w.new_root);
            auto const us = t.elapsedUs();

            BenchRow r;
            r.scenario   = "prover_createProof";
            r.run        = i;
            r.elapsedUs  = us;
            r.proofBytes = pd.proof_bytes.size();
            r.outcome    = pd.empty() ? "FAIL" : "OK";
            sink.append(r);

            BEAST_EXPECT(!pd.empty());
            log << "  run " << i << ": " << (us / 1000) << " ms, "
                << pd.proof_bytes.size() << " bytes" << std::endl;
        }
    }

    // Bench 2: per-proof verification cost (consensus hot path). Design
    // budget: 3 Miller-loop pairings on BN-128, ~30 ms.
    void
    testVerifierLatency()
    {
        testcase("RollupProver::verifyProof latency");

        RollupProver::initialize();
        CsvSink sink(csvPath());
        sink.writeHeader();

        // Generate ONE valid proof up front; reuse it across runs so we
        // measure verification (fast) without contaminating with
        // generation (slow).
        auto const w = buildHonestWitness(0xCAFE, 0xBABE, 5'000'000);
        auto const pd = RollupProver::createProof(
            w.old_note, w.new_note, w.leaf_pos,
            w.auth_path_old, w.auth_path_new,
            w.prev_root, w.new_root);
        BEAST_EXPECT(!pd.empty());

        auto const runs = numRuns();
        for (std::uint32_t i = 0; i < runs; ++i)
        {
            Stopwatch t;
            bool const ok = RollupProver::verifyProof(pd);
            auto const us = t.elapsedUs();

            BenchRow r;
            r.scenario   = "verifier_verifyProof";
            r.run        = i;
            r.elapsedUs  = us;
            r.proofBytes = pd.proof_bytes.size();
            r.outcome    = ok ? "VALID" : "INVALID";
            sink.append(r);

            BEAST_EXPECT(ok);
            log << "  run " << i << ": " << us << " us" << std::endl;
        }
    }

    // Bench 3: on-chain pipeline cost via the existing tampered-rejection
    // path. Measures preflight + preclaim wall-clock for a fully-real N=8
    // batch. This is the closest approximation to the "consensus hot path
    // with eight Poseidon verifies" cost that the current codebase allows
    // without API changes.
    //
    // The batch's slot-3 entry has its proof byte flipped, so preclaim
    // returns temBAD_PROOF — but only AFTER the verifier has verified
    // seven valid proofs and rejected the eighth. The 7 + 1 cost is what
    // we record.
    void
    testOnChainPipelineLatency()
    {
        testcase("BatchVerifier preflight+preclaim latency (tampered path)");

        using namespace jtx;

        RollupProver::initialize();
        CsvSink sink(csvPath());
        sink.writeHeader();

        auto const runs = numRuns();
        for (std::uint32_t i = 0; i < runs; ++i)
        {
            Env env(*this, supported_amendments() | featureZKRollup);
            Account const submitter("bench_submitter_" + std::to_string(i));
            env.fund(XRP(10000), submitter);
            env.close();

            auto sb = makeRealBatchTampered(/*batchId=*/1);

            auto tx = batchRollupTxJson(submitter, sb);

            Stopwatch t;
            env(tx, ter(temBAD_PROOF));
            auto const us = t.elapsedUs();

            BenchRow r;
            r.scenario  = "onchain_pipeline_n8";
            r.run       = i;
            r.elapsedUs = us;
            r.proofBytes =
                BATCH_SIZE * 192;  // kEntryProofSlotBytes from BatchVerifier
            // env.tx() is valid only after a transaction has been submitted;
            // capture the size of the serialised STTx.
            if (auto const stx = env.tx(); stx)
            {
                auto const ser = stx->getSerializer();
                r.txBytes = ser.size();
                r.feeDrops = stx->getFieldAmount(sfFee).xrp().drops();
            }
            r.outcome = "temBAD_PROOF";
            sink.append(r);

            log << "  run " << i << ": " << (us / 1000) << " ms, tx="
                << r.txBytes << " bytes" << std::endl;
        }
    }

    // Bench 4: baseline — 8x stock XRPL Payment. Same Env, same fee
    // schedule, measured the same way. This is what the rollup must beat
    // on (fee, ledger bytes, throughput) to justify the cryptographic
    // overhead.
    void
    testBaselinePaymentLatency()
    {
        testcase("Baseline 8x Payment latency");

        using namespace jtx;
        CsvSink sink(csvPath());
        sink.writeHeader();

        auto const runs = numRuns();
        for (std::uint32_t i = 0; i < runs; ++i)
        {
            Env env(*this);
            Account const src("base_src_" + std::to_string(i));
            env.fund(XRP(10000), src);
            env.close();

            std::vector<Account> dests;
            dests.reserve(8);
            for (int j = 0; j < 8; ++j)
                dests.emplace_back(
                    "base_dst_" + std::to_string(i) + "_" +
                    std::to_string(j));

            // Fund destinations so payments don't trip the create-reserve
            // threshold (a brand-new account needs ~10 XRP to be created;
            // we want to measure the steady-state Payment cost, not the
            // one-time creation cost).
            for (auto const& d : dests)
                env.fund(XRP(10000), d);
            env.close();

            std::size_t totalBytes = 0;
            std::int64_t totalFee = 0;

            Stopwatch t;
            for (auto const& d : dests)
            {
                env(pay(src, d, XRP(1)));
                if (auto const stx = env.tx(); stx)
                {
                    totalBytes += stx->getSerializer().size();
                    totalFee +=
                        stx->getFieldAmount(sfFee).xrp().drops();
                }
            }
            auto const us = t.elapsedUs();

            BenchRow r;
            r.scenario  = "baseline_payment_x8";
            r.run       = i;
            r.elapsedUs = us;
            r.txBytes   = totalBytes;
            r.feeDrops  = totalFee;
            r.outcome   = "tesSUCCESS";
            sink.append(r);

            log << "  run " << i << ": " << (us / 1000) << " ms total, "
                << totalBytes << " bytes, " << totalFee << " drops"
                << std::endl;
        }
    }

    // Bench 5: per-phase L2->L1 decomposition for a full N=8 batch. Times
    // each off-chain stage separately so the evaluation chapter can show
    // *where* the wall-clock goes, not just the aggregate. The on-chain
    // stages (preflight/preclaim/doApply + ledger close) for a genuinely
    // successful batch are measured on the live standalone node by
    // tools/phase5/bench_live_e2e.sh — the in-process suite cannot reach
    // tesSUCCESS without API changes, so we keep the
    // honest split: L2 phases here, completed L1 flow on the live node.
    void
    testL2PipelinePhases()
    {
        testcase("L2->L1 pipeline phase breakdown (N=8)");
        using namespace jtx;

        RollupProver::initialize();
        CsvSink sink(csvPath());
        sink.writeHeader();

        auto const runs = numRuns();
        for (std::uint32_t i = 0; i < runs; ++i)
        {
            BatchProof bp;
            bp.batchId  = 1;
            bp.prevRoot = uint256{};
            bp.txCount  = BATCH_SIZE;
            bp.entries.reserve(BATCH_SIZE);
            bp.proof.assign(BATCH_SIZE * kEntryProofSlotBytes, 0);

            std::array<uint256, BATCH_SIZE> newCommitments{};

            // Phase t1: witness construction (x8).
            std::vector<HonestWitness> ws;
            ws.reserve(BATCH_SIZE);
            Stopwatch tw;
            for (std::size_t j = 0; j < BATCH_SIZE; ++j)
                ws.push_back(buildHonestWitness(
                    /*seedOld=*/0xC300 + i * 16 + j,
                    /*seedNew=*/0xD400 + i * 16 + j,
                    /*value=*/1'000'000ULL * (j + 1)));
            auto const usWitness = tw.elapsedUs();

            // Phase t2: Groth16 proof generation (x8) — the dominant cost.
            Stopwatch tp;
            for (std::size_t j = 0; j < BATCH_SIZE; ++j)
            {
                auto pd = RollupProver::createProof(
                    ws[j].old_note, ws[j].new_note, ws[j].leaf_pos,
                    ws[j].auth_path_old, ws[j].auth_path_new,
                    ws[j].prev_root, ws[j].new_root);
                BEAST_EXPECT(!pd.empty());
                if (pd.proof_bytes.size() <= kEntryProofSlotBytes)
                    std::memcpy(
                        bp.proof.data() + j * kEntryProofSlotBytes,
                        pd.proof_bytes.data(), pd.proof_bytes.size());

                newCommitments[j] =
                    zkp::MerkleCircuit::fieldElementToUint256(
                        ws[j].new_note.commitment());
                RollupTxEntry e;
                e.commitment = newCommitments[j];
                e.nullifier  = zkp::MerkleCircuit::fieldElementToUint256(
                    ws[j].old_note.nullifier());
                e.value  = ws[j].new_note.value;
                e.txType = RollupTxType::Deposit;
                bp.entries.push_back(e);
            }
            auto const usProve = tp.elapsedUs();

            // newRoot from a fresh tree (matches the transactor's recipe).
            {
                zkp::rollup::RollupMerkleTree tree(kRollupTreeDepth);
                for (auto const& c : newCommitments)
                    tree.append(c);
                bp.newRoot = tree.root();
            }

            // Phase t3: serialise blob + compute batch hash.
            Stopwatch ts;
            auto const blob = bp.serialize();
            uint256 const bh = bp.computeBatchHash();
            auto const usSerialize = ts.elapsedUs();

            // Phase t4: sequencer Ed25519 signature.
            auto const seed = generateSeed("rollup-bench-sequencer-seed");
            auto const kp = generateKeyPair(KeyType::ed25519, seed);
            Stopwatch tsig;
            auto const sig =
                sign(kp.first, kp.second, Slice(bh.data(), bh.size()));
            auto const usSign = tsig.elapsedUs();
            BEAST_EXPECT(sig.size() == SEQUENCER_SIG_BYTES);

            auto const emit = [&](char const* phase, std::int64_t us) {
                BenchRow r;
                r.scenario   = "l2_pipeline_n8";
                r.run        = i;
                r.phase      = phase;
                r.elapsedUs  = us;
                r.nL2Txs     = BATCH_SIZE;
                r.proofBytes = BATCH_SIZE * kEntryProofSlotBytes;
                r.txBytes    = blob.size();
                r.outcome    = "OK";
                sink.append(r);
            };
            emit("witness", usWitness);
            emit("createProof", usProve);
            emit("serialize", usSerialize);
            emit("sign", usSign);
            emit("total_l2", usWitness + usProve + usSerialize + usSign);

            log << "  run " << i << ": witness=" << (usWitness / 1000)
                << "ms prove=" << (usProve / 1000) << "ms serialize="
                << usSerialize << "us sign=" << usSign << "us" << std::endl;
        }
    }

    // Bench 6: Merkle-tree work — rollup batch vs N independent L1 txs.
    //
    // The headline structural claim of the dissertation: a rollup commits N
    // L2 state transitions with a SINGLE on-chain Merkle-root write and a
    // SINGLE L1 transaction, whereas N un-batched transactions each write
    // their own root on their own ledger entry. The Poseidon *compute* is
    // identical (depth * N hashes either way) — the saving is in on-chain
    // write/transaction amplification (N x fewer), which this bench makes
    // explicit via the root_writes / state_writes columns.
    void
    testMerkleWork()
    {
        testcase("Merkle work: rollup batch vs N independent L1 txs");

        PoseidonHash::initialize();
        CsvSink sink(csvPath());
        sink.writeHeader();

        using zkp::rollup::RollupMerkleTree;
        constexpr std::size_t N = BATCH_SIZE;
        auto const depth = static_cast<std::uint64_t>(kRollupTreeDepth);

        // Pre-seed a depth-32 tree with the 8 genesis null-notes — exactly
        // the state doApply() starts from before update_leaf(0..7).
        auto preseed = [](RollupMerkleTree& t) {
            for (std::uint64_t g = 0; g < zkp::rollup::kRollupBatchSize; ++g)
                t.append(zkp::MerkleCircuit::fieldElementToUint256(
                    RollupNote::createRandom(0, g).commitment()));
        };

        // The N fresh leaf commitments this batch installs.
        std::array<uint256, N> leaves{};
        for (std::size_t j = 0; j < N; ++j)
            leaves[j] = zkp::MerkleCircuit::fieldElementToUint256(
                RollupNote::createRandom(1'000'000ULL * (j + 1), 0xE100 + j)
                    .commitment());

        auto const runs = numRuns();
        for (std::uint32_t i = 0; i < runs; ++i)
        {
            // ROLLUP: one shared tree, N update_leaf, ONE root/state write.
            RollupMerkleTree rollupTree(kRollupTreeDepth);
            preseed(rollupTree);
            Stopwatch tr;
            for (std::size_t j = 0; j < N; ++j)
                rollupTree.update_leaf(j, leaves[j]);
            (void)rollupTree.root();
            auto const usRollup = tr.elapsedUs();

            {
                BenchRow r;
                r.scenario       = "merkle_rollup_n8";
                r.run            = i;
                r.phase          = "update_leaf_x8";
                r.elapsedUs      = usRollup;
                r.nL2Txs         = N;
                r.merkleUpdates  = N;
                r.poseidonHashes = depth * N;  // recomputePathFromLeaf: depth each
                r.rootWrites     = 1;          // single sfRollupRoot/sfTreeFrontier
                r.stateWrites    = 1;          // single RollupState SLE
                r.outcome        = "OK";
                sink.append(r);
            }

            // WITHOUT ROLLUP: same N commits, but each is an independent L1
            // transaction writing its own root on its own ledger entry. The
            // per-commit compute is identical; the on-chain footprint is N x.
            RollupMerkleTree baseTree(kRollupTreeDepth);
            preseed(baseTree);
            Stopwatch tb;
            for (std::size_t j = 0; j < N; ++j)
            {
                baseTree.update_leaf(j, leaves[j]);
                (void)baseTree.root();  // each intermediate root is "written"
            }
            auto const usBaseline = tb.elapsedUs();

            {
                BenchRow r;
                r.scenario       = "merkle_baseline_n8";
                r.run            = i;
                r.phase          = "independent_x8";
                r.elapsedUs      = usBaseline;
                r.nL2Txs         = N;
                r.merkleUpdates  = N;
                r.poseidonHashes = depth * N;
                r.rootWrites     = N;  // N separate root writes
                r.stateWrites    = N;  // N separate L1 state writes
                r.outcome        = "OK";
                sink.append(r);
            }

            log << "  run " << i << ": rollup(1 root write)=" << usRollup
                << "us  baseline(" << N << " root writes)=" << usBaseline
                << "us" << std::endl;
        }
    }

    // Helpers: real-batch construction (mirrors
    // BatchVerifier_test::makeRealSignedBatch, with slot-3 tamper).

    struct SignedBatch
    {
        BatchProof bp;
        std::vector<std::uint8_t> pubKey;
        std::vector<std::uint8_t> blob;
    };

    static constexpr std::size_t kEntryProofSlotBytes = 192;

    SignedBatch
    makeRealBatchTampered(std::uint32_t batchId)
    {
        SignedBatch sb;
        sb.bp.batchId  = batchId;
        // prevRoot must equal the genesis rollup root so preclaim's
        // root-chain check passes and execution reaches the Groth16 verifier
        // (which then rejects the tampered slot-3 proof with temBAD_PROOF).
        // uint256{} would short-circuit earlier with tecFAILED_PROCESSING.
        sb.bp.prevRoot = zkp::rollup::kGenesisRollupRoot();
        sb.bp.txCount  = BATCH_SIZE;
        sb.bp.entries.reserve(BATCH_SIZE);
        sb.bp.proof.assign(BATCH_SIZE * kEntryProofSlotBytes, 0);

        std::array<uint256, BATCH_SIZE> newCommitments{};

        for (std::size_t i = 0; i < BATCH_SIZE; ++i)
        {
            auto const w = buildHonestWitness(
                /*seedOld=*/0xC3 + batchId * 100 + i,
                /*seedNew=*/0xD4 + batchId * 100 + i,
                /*value=*/1'000'000ULL * (i + 1));

            auto pd = RollupProver::createProof(
                w.old_note, w.new_note, w.leaf_pos,
                w.auth_path_old, w.auth_path_new,
                w.prev_root, w.new_root);

            if (pd.proof_bytes.size() > kEntryProofSlotBytes)
                throw std::runtime_error("proof exceeds 192-byte slot");

            std::memcpy(
                sb.bp.proof.data() + i * kEntryProofSlotBytes,
                pd.proof_bytes.data(),
                pd.proof_bytes.size());

            newCommitments[i] =
                zkp::MerkleCircuit::fieldElementToUint256(
                    w.new_note.commitment());

            RollupTxEntry e;
            e.commitment = newCommitments[i];
            e.nullifier  = zkp::MerkleCircuit::fieldElementToUint256(
                w.old_note.nullifier());
            e.value      = w.new_note.value;
            e.txType     = RollupTxType::Deposit;
            sb.bp.entries.push_back(e);
        }

        // Compute newRoot via a separate tree (matches the transactor).
        zkp::rollup::RollupMerkleTree tree(kRollupTreeDepth);
        for (auto const& c : newCommitments)
            tree.append(c);
        sb.bp.newRoot = tree.root();

        // Tamper slot 3.
        constexpr std::size_t targetEntry = 3;
        constexpr std::size_t flipOffset  = 80;
        sb.bp.proof[targetEntry * kEntryProofSlotBytes + flipOffset] ^= 0xFF;

        signWithTestSequencer(sb);
        return sb;
    }

    static void
    signWithTestSequencer(SignedBatch& sb)
    {
        using namespace jtx;
        auto const seed = generateSeed("rollup-bench-sequencer-seed");
        auto const kp   = generateKeyPair(KeyType::ed25519, seed);
        sb.pubKey.assign(kp.first.data(), kp.first.data() + kp.first.size());

        uint256 const bh = sb.bp.computeBatchHash();
        auto const sig = sign(kp.first, kp.second, Slice(bh.data(), bh.size()));
        if (sig.size() != SEQUENCER_SIG_BYTES)
            throw std::runtime_error("unexpected Ed25519 sig size");
        std::memcpy(sb.bp.sequencerSig.data(), sig.data(),
                    SEQUENCER_SIG_BYTES);
        sb.blob = sb.bp.serialize();
    }

    static Json::Value
    batchRollupTxJson(jtx::Account const& submitter, SignedBatch const& sb)
    {
        Json::Value tx;
        tx[jss::TransactionType] = "BatchRollup";
        tx[jss::Account]         = submitter.human();
        tx[jss::BatchId]         = sb.bp.batchId;
        tx[jss::PrevRoot]        = to_string(sb.bp.prevRoot);
        tx[jss::RollupRoot]      = to_string(sb.bp.newRoot);
        tx[jss::TxCount]         = sb.bp.txCount;
        tx[jss::SequencerPubKey] = strHex(sb.pubKey);
        tx[jss::BatchProof]      = strHex(sb.blob);
        return tx;
    }

public:
    void
    run() override
    {
        testProverLatency();
        testVerifierLatency();
        testOnChainPipelineLatency();
        testBaselinePaymentLatency();
        testL2PipelinePhases();
        testMerkleWork();
    }
};

// `manual` priority — the prover/verifier passes generate real Groth16
// proofs which are slow (3-5s each at depth=32). Keep it out of the default
// fast-test rotation. Invoke explicitly:
//     ./rippled --unittest=ripple.zkp_rollup.RollupBench
BEAST_DEFINE_TESTSUITE_MANUAL(RollupBench, zkp_rollup, ripple);

}  // namespace test
}  // namespace ripple