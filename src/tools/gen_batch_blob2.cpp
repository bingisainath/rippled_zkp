// Copyright 2026 Sainath, Trinity College Dublin
// SPDX-License-Identifier: ISC
//
// gen_batch_blob2 — off-node generator for a Track 2 (Option A) ttBATCH_ROLLUP2
// sfBatchProof blob. Mirrors gen_batch_blob.cpp (Track 1) but builds ONE
// monolithic proof via RollupSequencer2 instead of N per-entry proofs.
//
// Emits KEY=value lines on stdout for a demo shell script to parse:
//   BLOB=<hex>        the sfBatchProof blob
//   PUB=<hex>         33-byte sequencer Ed25519 public key
//   PREV_ROOT=<hex>   prevRoot (uint256)
//   NEW_ROOT=<hex>    newRoot  (uint256)
//   BATCH_ID=<n>
//   TX_COUNT=<n>
//
// Options:
//   --gen-keys              Initialise/generate the BatchCircuit Groth16 keys
//                           at the default path, then exit (one-time setup).
//   --genesis-root          Print the empty-tree genesis root and exit.
//   --deposits N            Number of deposit entries (1..8, default 8).
//   --batch-id N            Batch id (default 1). NOTE: this tool is stateless
//                           and always builds from the GENESIS root, so only
//                           batch-id 1 will apply on a fresh node.
//   --deposit-value-base V  First deposit's drops (default 1000000); entry i
//                           deposits V + i.
//
// Key path: /tmp/rippled_rollup_batch_keys (the node's default — so the tool
// and node share keys; the node's onStart generates them if absent).

#include <libxrpl/zkp/rollup/BatchCircuitProver.h>
#include <libxrpl/zkp/rollup/BatchProof2.h>
#include <libxrpl/zkp/rollup/RollupSequencer2.h>
#include <libxrpl/zkp/rollup/RollupState2.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

using namespace ripple::zkp::rollup;

namespace {

constexpr std::size_t kDepth = 16;  // matches the node's default prover shape

std::string
toHex(std::vector<std::uint8_t> const& v)
{
    std::ostringstream ss;
    for (auto b : v)
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(b);
    return ss.str();
}

std::string
toHex(ripple::uint256 const& u)
{
    std::vector<std::uint8_t> v(u.begin(), u.end());
    return toHex(v);
}

void
initCrypto()
{
    libff::alt_bn128_pp::init_public_params();
    BabyJubjub::initialize();
    PoseidonHash::initialize();
}

// Deterministic demo user keys.
FieldT
userKey(std::size_t i)
{
    return FieldT("770000110022003300") + FieldT(i);
}

// What a deposit for demo user `i` will look like. SINGLE SOURCE OF TRUTH for
// both QUOTE and PROVE — they must never drift, because L1 now requires each
// Deposit entry to match a queued ttROLLUP_DEPOSIT2 claim on BOTH apk_x and
// drops exactly. If QUOTE reported one amount and PROVE built another, the
// batch would be rejected with tecFAILED_PROCESSING.
//
// The nonce is read from the sequencer's own account view (0 for a leaf that
// does not exist yet, else the current nonce). Reading does not mutate, so
// QUOTE is side-effect free.
struct DepositSpec
{
    FieldT key;
    FieldT apkX;
    std::uint64_t drops;
    std::uint64_t nonce;
};

// `userOffset` shifts WHICH leaves are credited without changing the amounts:
// drops depends on the slot index, not the user. That separation is what lets
// the demo isolate the attribution guard — a batch crediting the wrong leaf for
// the RIGHT amount passes the aggregate check and can only be caught by the
// per-claim apk_x match. Default 0 reproduces the original behaviour exactly.
std::vector<DepositSpec>
depositSpecs(
    ripple::zkp::rollup::RollupSequencer2 const& seq,
    std::uint32_t nDeposits,
    std::uint32_t userOffset = 0)
{
    std::vector<DepositSpec> out;
    out.reserve(nDeposits);
    for (std::uint32_t i = 0; i < nDeposits; ++i)
    {
        DepositSpec s;
        s.key = userKey(userOffset + i);
        s.apkX = EdDSA::derivePublicKey(s.key).x;
        s.drops = 1'000'000 + i;
        s.nonce = 0;
        if (auto av = seq.account(s.apkX))
            s.nonce = av->nonce;
        out.push_back(s);
    }
    return out;
}

// Default withdrawal payout target: the standalone node's genesis account.
// It always exists, so a withdrawal credits it rather than trying to create
// an AccountRoot that would need to clear accountReserve.
ripple::AccountID const kGenesisAccount =
    *ripple::parseBase58<ripple::AccountID>(
        "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh");

}  // namespace

int
main(int argc, char** argv)
{
    initCrypto();

    if (argc >= 2 && std::string(argv[1]) == "--genesis-root")
    {
        std::cout << toHex(emptyAccountTreeRoot(kDepth)) << "\n";
        return 0;
    }

    if (argc >= 2 && std::string(argv[1]) == "--gen-keys")
    {
        std::cerr << "[gen_batch_blob2] initialising BatchCircuit keys "
                     "(one-time, ~35s if absent)…\n";
        BatchCircuitProver::initialize(
            BatchCircuitProver::defaultKeyPath(), 8, kDepth);
        std::cerr << "[gen_batch_blob2] keys ready ("
                  << BatchCircuitProver::constraintCount()
                  << " constraints).\n";
        return 0;
    }

    if (argc >= 2 && std::string(argv[1]) == "--serve")
    {
        // Resident prover daemon (what a production sequencer does): pay the
        // startup cost ONCE — curve init + deserialising the ~117 MB proving
        // key, measured at 80 s on this VM — then answer PROVE commands over
        // stdin. Per-batch cost drops to the pure prove step.
        //
        // MEASURED (phase 7, 372,404 constraints, depth 16, N=8):
        //   61.5 s mean over 5 batches, spread 0.41 s (0.7%).
        // That spread is the point: a batch of 8 NoOps costs the same as one
        // carrying a real transfer, because the circuit is FIXED-SIZE — every
        // slot runs the full EdDSA check and both Merkle paths regardless of
        // content. Prove time tracks batch CAPACITY, never batch content, so
        // a half-empty batch costs exactly what a full one does.
        //
        // Because the RollupSequencer2 instance persists across commands, its
        // account tree chains naturally: PROVE n, PROVE n+1, … produce batches
        // whose prevRoot/newRoot link up, so multi-batch demos work without
        // restarting the node. Deposit nonces are read from the sequencer's
        // own account view (0 for a new account, else the current leaf nonce).
        //
        // Protocol (line-based):
        //   in : PROVE <deposits 0..8> <batchId> [withdrawals 0..8] [destB58]
        //   out: the same KEY=value block as one-shot mode, then "END"
        //   in : QUOTE <deposits 0..8> <batchId>
        //   out: CLAIM=<apk_x hex>,<drops>  (one per deposit, in order), "END"
        //   in : BALANCES
        //   out: ACCT=<apk_x hex>,<index>,<balance>,<nonce>  (one per account)
        //        ROOT=<hex>, then "END"
        //   in : EXIT   (or EOF)  → quit
        //
        // QUOTE exists because deposits are now BACKED: a batch may credit an
        // L2 leaf only if a ttROLLUP_DEPOSIT2 already escrowed real XRP naming
        // that exact apk_x and amount. The shell cannot compute apk_x (Baby
        // Jubjub arithmetic lives here), so it asks first, submits the L1
        // deposits verbatim, and only then calls PROVE.
        //
        // Deposits are drawn from users 0..d-1 and withdrawals from users
        // d..d+w-1, so the two sets are disjoint: a user cannot appear twice
        // in one batch, because both requests would carry the same nonce and
        // the second would fail admission. Withdrawals therefore only succeed
        // for users a PRIOR batch already funded — which is the point of the
        // 8-deposit → 4-withdraw → 4+4 mixed demo sequence.
        //
        // destB58 defaults to the genesis account: it already exists on a
        // standalone node, so the withdrawal credits an existing AccountRoot
        // and never trips the accountReserve floor that creating a fresh
        // destination would (tecNO_DST_INSUF_XRP for sub-reserve values).
        std::cerr << "[gen_batch_blob2] --serve: loading Groth16 keys once…\n";
        BatchCircuitProver::initialize(
            BatchCircuitProver::defaultKeyPath(), 8, kDepth);
        RollupSequencer2 seq(kDepth);
        std::cout << "READY constraints="
                  << BatchCircuitProver::constraintCount() << "\n"
                  << std::flush;

        std::string line;
        while (std::getline(std::cin, line))
        {
            std::istringstream is(line);
            std::string cmd;
            is >> cmd;
            if (cmd == "EXIT")
                break;

            // QUOTE <deposits 0..8> <batchId>
            //
            // Report what a subsequent PROVE will credit, WITHOUT proving.
            // The shell needs this because apk_x comes from Baby Jubjub curve
            // arithmetic that exists only here — it cannot derive the claim
            // values itself, and L1 now requires them to match exactly.
            //
            // Side-effect free: depositSpecs only reads the account view.
            if (cmd == "QUOTE")
            {
                std::uint32_t qDeposits = 0, qBid = 0, qOffset = 0;
                if (!(is >> qDeposits >> qBid) || qDeposits > BATCH2_SIZE)
                {
                    std::cout << "ERROR=expected: QUOTE <deposits 0..8> "
                                 "<batchId> [userOffset]\n"
                              << "END\n"
                              << std::flush;
                    continue;
                }
                is >> qOffset;  // optional; lets a caller quote leaves OUTSIDE
                                // the range a normal batch credits, so a demo
                                // claim cannot collide with the real flow
                for (auto const& s : depositSpecs(seq, qDeposits, qOffset))
                {
                    std::cout
                        << "CLAIM="
                        << ripple::to_string(
                               PoseidonHash::fieldToUint256(s.apkX))
                        << "," << s.drops << "\n";
                }
                std::cout << "END\n" << std::flush;
                continue;
            }

            // BALANCES — the sequencer's OFF-CHAIN account state.
            //
            // L1 stores only the root and cannot see these figures; the proof
            // is what makes this report non-repudiable. Read-only.
            if (cmd == "BALANCES")
            {
                for (auto const& a : seq.accounts())
                {
                    std::cout << "ACCT=" << ripple::to_string(a.apkX) << ","
                              << a.index << "," << a.balance << ","
                              << a.nonce << "\n";
                }
                std::cout << "ROOT=" << ripple::to_string(seq.root()) << "\n"
                          << "END\n"
                          << std::flush;
                continue;
            }

            std::uint32_t nDeposits = 0, bid = 0, nWithdrawals = 0;
            std::uint32_t userOffset = 0;
            bool allowEmpty = false;
            std::string destB58;

            // Withdrawals normally draw the slots right after the deposits in
            // THIS batch (u = nDeposits + i, the original PROVE convention).
            // MIXED needs to place withdrawals and deposits at INDEPENDENT
            // user ranges (e.g. 2 brand-new deposits at offset 8, alongside 2
            // withdrawals from already-funded users at offset 0), so it sets
            // this explicitly instead.
            std::uint32_t withdrawOffset = 0;
            bool withdrawOffsetSet = false;

            // Transfer list. A transfer touches NO L1 account: it consumes no
            // deposit claim and pays out of no escrow, so it is the one entry
            // type that moves the root without moving any XRP. Generalised to
            // a list (rather than one xFrom/xTo/xDrops) so MIXED can combine
            // several transfers with deposits and withdrawals in one proof —
            // the circuit and buildBatch already support any per-slot mix of
            // types; only this tool's single-shot commands didn't expose it.
            std::vector<std::tuple<std::uint32_t, std::uint32_t, std::uint64_t>>
                transfers;

            // BOOTSTRAP <batchId> — a NoOp-only batch. It anchors the
            // sequencer key and the escrow account on L1 without crediting any
            // L2 balance, which backed deposits require before the first
            // ttROLLUP_DEPOSIT2 can be accepted. A NoOp leaves its slot empty,
            // so this does NOT move the root.
            if (cmd == "BOOTSTRAP")
            {
                if (!(is >> bid))
                {
                    std::cout << "ERROR=expected: BOOTSTRAP <batchId>\n"
                              << "END\n"
                              << std::flush;
                    continue;
                }
                allowEmpty = true;
            }
            // PROVE_MISATTR <batchId> — DEMO ONLY. Builds a one-deposit batch
            // crediting user 5 for exactly the amount user 0's claim carries.
            // The totals still balance, so the aggregate check passes; only the
            // per-claim apk_x match can reject it. This is the misattribution
            // attack: the depositor paid naming their own leaf, the sequencer
            // credited a different one.
            else if (cmd == "PROVE_MISATTR")
            {
                if (!(is >> bid))
                {
                    std::cout << "ERROR=expected: PROVE_MISATTR <batchId>\n"
                              << "END\n"
                              << std::flush;
                    continue;
                }
                nDeposits = 1;
                userOffset = 5;
            }
            // TRANSFER <fromUser> <toUser> <drops> <batchId> — Phase 7.
            // Both leaves must already hold a balance (only deposits create
            // accounts, and the circuit cannot prove a credit into an empty
            // slot). Pure L2: the pool total and every L1 balance are
            // unchanged, only the root moves.
            else if (cmd == "TRANSFER")
            {
                std::uint32_t tFrom = 0, tTo = 0;
                std::uint64_t tDrops = 0;
                if (!(is >> tFrom >> tTo >> tDrops >> bid))
                {
                    std::cout << "ERROR=expected: TRANSFER <fromUser> "
                                 "<toUser> <drops> <batchId>\n"
                              << "END\n"
                              << std::flush;
                    continue;
                }
                if (tFrom == tTo)
                {
                    std::cout << "ERROR=self-transfer is not supported\n"
                              << "END\n"
                              << std::flush;
                    continue;
                }
                transfers.push_back({tFrom, tTo, tDrops});
                allowEmpty = true;  // the transfer itself fills a slot
            }
            // MIXED <batchId> <deposits> <depositOffset> <withdrawals>
            //       <withdrawOffset> <numTransfers> [<from> <to> <drops>]...
            //
            // Combines deposits, withdrawals and (multiple) transfers in ONE
            // proof — demonstrating all three settlement patterns land as a
            // single batch, not three separate ones. The three user ranges
            // (deposit creators, withdrawal signers, transfer senders) MUST be
            // pairwise disjoint: each signs at most once per batch, or the
            // second occurrence carries a stale nonce and the proof becomes
            // unsatisfiable (same rule PROVE already enforces for deposits
            // vs withdrawals). Transfer RECIPIENTS have no such restriction —
            // they never sign, so the same recipient may appear more than
            // once, and may also be a sender/depositor/withdrawer elsewhere
            // in the same batch.
            else if (cmd == "MIXED")
            {
                std::uint32_t nTransfers = 0;
                if (!(is >> bid >> nDeposits >> userOffset >> nWithdrawals >>
                      withdrawOffset >> nTransfers))
                {
                    std::cout
                        << "ERROR=expected: MIXED <batchId> <deposits> "
                           "<depositOffset> <withdrawals> <withdrawOffset> "
                           "<numTransfers> [<from> <to> <drops>]...\n"
                        << "END\n"
                        << std::flush;
                    continue;
                }
                withdrawOffsetSet = true;
                bool badSpec = false;
                for (std::uint32_t k = 0; k < nTransfers; ++k)
                {
                    std::uint32_t tFrom = 0, tTo = 0;
                    std::uint64_t tDrops = 0;
                    if (!(is >> tFrom >> tTo >> tDrops))
                    {
                        std::cout << "ERROR=MIXED: missing transfer spec #"
                                  << k << "\n"
                                  << "END\n"
                                  << std::flush;
                        badSpec = true;
                        break;
                    }
                    if (tFrom == tTo)
                    {
                        std::cout << "ERROR=self-transfer is not supported "
                                     "(spec #"
                                  << k << ")\n"
                                  << "END\n"
                                  << std::flush;
                        badSpec = true;
                        break;
                    }
                    transfers.push_back({tFrom, tTo, tDrops});
                }
                if (badSpec)
                    continue;
                allowEmpty = true;
            }
            else if (cmd != "PROVE" || !(is >> nDeposits >> bid))
            {
                std::cout << "ERROR=expected: PROVE <deposits 0..8> <batchId> "
                             "[withdrawals 0..8] [destB58] | BOOTSTRAP "
                             "<batchId> | PROVE_MISATTR <batchId> | TRANSFER "
                             "<fromUser> <toUser> <drops> <batchId> | MIXED "
                             "<batchId> <deposits> <depositOffset> "
                             "<withdrawals> <withdrawOffset> <numTransfers> "
                             "[<from> <to> <drops>]... | QUOTE <deposits> "
                             "<batchId> | BALANCES | EXIT\n"
                          << "END\n"
                          << std::flush;
                continue;
            }
            else
            {
                is >> nWithdrawals;  // optional; leaves 0 on absence
                is >> destB58;       // optional; empty on absence
            }

            if (!withdrawOffsetSet)
                withdrawOffset = nDeposits;  // original PROVE convention

            std::uint32_t const total =
                nDeposits + nWithdrawals +
                static_cast<std::uint32_t>(transfers.size());
            if ((total < 1 && !allowEmpty) || total > BATCH2_SIZE)
            {
                std::cout << "ERROR=deposits+withdrawals must be 1.."
                          << BATCH2_SIZE << " (got " << total << ")\n"
                          << "END\n"
                          << std::flush;
                continue;
            }

            ripple::AccountID dest = kGenesisAccount;
            if (!destB58.empty())
            {
                auto parsed = ripple::parseBase58<ripple::AccountID>(destB58);
                if (!parsed)
                {
                    std::cout << "ERROR=bad destination account: " << destB58
                              << "\n"
                              << "END\n"
                              << std::flush;
                    continue;
                }
                dest = *parsed;
            }

            std::vector<SequencerRequest> reqs;

            {
                bool transferError = false;
                for (auto const& [xFrom, xTo, xDrops] : transfers)
                {
                    BjjPoint const fromApk =
                        EdDSA::derivePublicKey(userKey(xFrom));
                    BjjPoint const toApk = EdDSA::derivePublicKey(userKey(xTo));
                    auto const fromAv = seq.account(fromApk.x);
                    auto const toAv = seq.account(toApk.x);

                    if (!fromAv || fromAv->balance < xDrops)
                    {
                        std::cout
                            << "ERROR=user " << xFrom
                            << " has no L2 balance (or too little) to send "
                            << xDrops << " drops\n"
                            << "END\n"
                            << std::flush;
                        transferError = true;
                        break;
                    }
                    if (!toAv)
                    {
                        std::cout
                            << "ERROR=user " << xTo
                            << " has no L2 leaf — a transfer cannot create "
                               "one; fund it with a deposit first\n"
                            << "END\n"
                            << std::flush;
                        transferError = true;
                        break;
                    }

                    SequencerRequest sr;
                    // destination stays zero: no L1 account is involved. The
                    // signed `dest` carries the RECIPIENT'S apk_x, and the
                    // circuit's is_xfer*(to_x - dest) = 0 binds the credited
                    // leaf to it.
                    sr.req = SignedRequest::make(
                        userKey(xFrom),
                        toApk.x,
                        xDrops,
                        fromAv->nonce,
                        RequestType::Transfer);
                    reqs.push_back(sr);
                }
                if (transferError)
                    continue;
            }

            for (auto const& s : depositSpecs(seq, nDeposits, userOffset))
            {
                SequencerRequest sr;
                sr.req = SignedRequest::make(
                    s.key, s.apkX, s.drops, s.nonce, RequestType::Deposit);
                reqs.push_back(sr);
            }
            bool withdrawError = false;
            for (std::uint32_t i = 0; i < nWithdrawals; ++i)
            {
                std::uint32_t const u = withdrawOffset + i;
                SequencerRequest sr;
                BjjPoint apk = EdDSA::derivePublicKey(userKey(u));
                auto av = seq.account(apk.x);
                if (!av || av->balance == 0)
                {
                    std::cout << "ERROR=user " << u
                              << " has no L2 balance to withdraw — fund it in "
                                 "an earlier batch first\n"
                              << "END\n"
                              << std::flush;
                    reqs.clear();
                    withdrawError = true;
                    break;
                }
                // Withdraw half the balance so the leaf survives for later
                // batches; the signed `dest` must encode the L1 payout target
                // (AccountLeaf.h canonical encoding) or preflight rejects it.
                sr.destination = dest;
                sr.req = SignedRequest::make(
                    userKey(u),
                    accountIdToField(dest),
                    av->balance / 2,
                    av->nonce,
                    RequestType::Withdraw);
                reqs.push_back(sr);
            }
            // An error already printed END above (withdrawal admission, or a
            // bad transfer spec) must always abort here — regardless of
            // allowEmpty, which exists for the LEGITIMATE empty case
            // (BOOTSTRAP) only.
            if (withdrawError)
                continue;
            // BOOTSTRAP legitimately has no requests — buildBatch pads all 8
            // slots with NoOps. Any other command reaching here empty hit the
            // withdrawal-admission error above and already reported it.
            if (reqs.empty() && !allowEmpty)
                continue;

            std::cerr << "[gen_batch_blob2] PROVE batch " << bid << " ("
                      << nDeposits << " deposits, " << nWithdrawals
                      << " withdrawals, " << transfers.size()
                      << " transfers) — key already resident, "
                         "pure proving…\n";
            auto bp = seq.buildBatch(reqs, bid);
            if (!bp)
            {
                std::cout << "ERROR=buildBatch failed (admission or prover)\n"
                          << "END\n"
                          << std::flush;
                continue;
            }
            auto const blob = bp->serialize();
            std::cout << "BLOB=" << toHex(blob) << "\n"
                      << "PUB=" << toHex(seq.publicKey()) << "\n"
                      << "PREV_ROOT=" << toHex(bp->prevRoot) << "\n"
                      << "NEW_ROOT=" << toHex(bp->newRoot) << "\n"
                      << "BATCH_ID=" << bp->batchId << "\n"
                      << "TX_COUNT=" << bp->txCount << "\n"
                      << "DEPOSITS=" << nDeposits << "\n"
                      << "WITHDRAWALS=" << nWithdrawals << "\n"
                      << "TRANSFERS=" << transfers.size() << "\n"
                      << "END\n"
                      << std::flush;
        }
        return 0;
    }

    std::uint32_t batchId = 1;
    std::uint32_t deposits = 8;
    std::uint64_t depositValueBase = 1'000'000;

    for (int a = 1; a < argc; ++a)
    {
        std::string arg = argv[a];
        if (arg == "--batch-id" && a + 1 < argc)
            batchId = static_cast<std::uint32_t>(std::stoul(argv[++a]));
        else if (arg == "--deposits" && a + 1 < argc)
            deposits = static_cast<std::uint32_t>(std::stoul(argv[++a]));
        else if (arg == "--deposit-value-base" && a + 1 < argc)
            depositValueBase = std::stoull(argv[++a]);
        else
        {
            std::cerr << "[gen_batch_blob2] unknown/incomplete arg: " << arg
                      << "\n";
            return 2;
        }
    }

    if (deposits < 1 || deposits > BATCH2_SIZE)
    {
        std::cerr << "[gen_batch_blob2] --deposits must be in [1, "
                  << BATCH2_SIZE << "]\n";
        return 2;
    }

    // Load (or generate) keys and build the batch.
    BatchCircuitProver::initialize(
        BatchCircuitProver::defaultKeyPath(), 8, kDepth);

    RollupSequencer2 seq(kDepth);
    std::vector<SequencerRequest> reqs;
    for (std::uint32_t i = 0; i < deposits; ++i)
    {
        SequencerRequest sr;
        BjjPoint apk = EdDSA::derivePublicKey(userKey(i));
        sr.req = SignedRequest::make(
            userKey(i), apk.x, depositValueBase + i, 0,
            RequestType::Deposit);
        reqs.push_back(sr);
    }

    std::cerr << "[gen_batch_blob2] building batch " << batchId << " with "
              << deposits << " deposit(s) + " << (BATCH2_SIZE - deposits)
              << " NoOp pad(s); proving (~62s at depth " << kDepth << ")…\n";

    auto bp = seq.buildBatch(reqs, batchId);
    if (!bp)
    {
        std::cerr << "[gen_batch_blob2] ERROR: buildBatch failed\n";
        return 1;
    }

    auto const blob = bp->serialize();

    std::cout << "BLOB=" << toHex(blob) << "\n";
    std::cout << "PUB=" << toHex(seq.publicKey()) << "\n";
    std::cout << "PREV_ROOT=" << toHex(bp->prevRoot) << "\n";
    std::cout << "NEW_ROOT=" << toHex(bp->newRoot) << "\n";
    std::cout << "BATCH_ID=" << bp->batchId << "\n";
    std::cout << "TX_COUNT=" << bp->txCount << "\n";

    std::cerr << "[gen_batch_blob2] blob=" << blob.size()
              << " bytes (proof=" << bp->proof.size() << "B). Done.\n";
    return 0;
}
