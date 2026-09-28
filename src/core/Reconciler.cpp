#include "Reconciler.h"
#include <spdlog/spdlog.h>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <thread>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <algorithm>

Reconciler::Reconciler(IViolationStore& store, std::string_view hmacKey)
    : store_(store) {
    orphanSeverity_ = Severity::Critical;
    missingSeverity_ = Severity::Medium;

    if (!hmacKey.empty()) {
        // Decode base64
        std::string decoded;
        decoded.resize(hmacKey.size());
        int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()),
                                  reinterpret_cast<const unsigned char*>(hmacKey.data()), hmacKey.size());
        if (len == 32) {
            std::copy_n(reinterpret_cast<const uint8_t*>(decoded.data()), 32, hmacKey_.begin());
            hasHmacKey_ = true;
            SPDLOG_INFO("HMAC-SHA256 enabled for integrity hashes");
        } else {
            SPDLOG_WARN("Invalid HMAC key length (decoded: {} bytes, expected 32), falling back to SHA-256", len);
        }
    } else {
        SPDLOG_WARN("No HMAC key configured, using SHA-256 without secret (not tamper-proof)");
    }
}

std::string Reconciler::generateRunID() {
    try {
        std::random_device rd;
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
        auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();

        std::seed_seq seed{
            rd(), rd(), rd(), rd(),
            static_cast<unsigned>(nanos & 0xFFFFFFFFu),
            static_cast<unsigned>(nanos >> 32),
            static_cast<unsigned>(std::hash<std::thread::id>{}(std::this_thread::get_id()))
        };

        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<uint64_t> dist;

        std::ostringstream oss;
        oss << "RUN_" << std::hex << nanos << "_" << dist(rng);
        return oss.str();
    } catch (...) {
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
        auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        std::ostringstream oss;
        oss << "RUN_" << std::hex << nanos << "_fallback";
        return oss.str();
    }
}

std::string Reconciler::sha256(std::string_view data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : digest) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string Reconciler::hmacSha256(const uint8_t* key, size_t keyLen, std::string_view data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;

    HMAC(EVP_sha256(), key, static_cast<int>(keyLen),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         digest, &len);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return oss.str();
}

std::string Reconciler::computeHash(std::string_view uid, ViolationType type, Severity severity) {
    std::string data = std::string(uid) + "|" + toString(type) + "|" + toString(severity);

    if (hasHmacKey_) {
        return hmacSha256(hmacKey_.data(), hmacKey_.size(), data);
    }
    return sha256(data);
}

Result<Reconciler::ReconciliationResult> Reconciler::runReconciliation(
    const std::unordered_map<std::string, Identity>& hrSource,
    const std::unordered_map<std::string, Identity>& targetSystem,
    RunMode mode
) {
    if (hrSource.empty()) {
        return Result<ReconciliationResult>::err(Error{ "VALIDATION", "HR source empty" });
    }

    ReconciliationResult result;
    result.runId = generateRunID();

    SPDLOG_INFO("Starting reconciliation run: {}", result.runId);

    if (mode == RunMode::DryRun) {
        SPDLOG_INFO("DRY-RUN mode: no database writes will be performed");
    }

    auto runRecord = RunRecord{ result.runId, "HR_API", "TARGET_SYSTEM" };
    if (mode != RunMode::DryRun) {
        if (auto r = store_.startRun(runRecord); r.hasError()) {
            return Result<ReconciliationResult>::err(r.error());
        }
        if (auto r = store_.beginTransaction(); r.hasError()) {
            store_.completeRun(result.runId, RunStatus::Failed);
            return Result<ReconciliationResult>::err(r.error());
        }
        if (auto r = store_.prepareBulkInsert(); r.hasError()) {
            store_.rollbackTransaction();
            store_.completeRun(result.runId, RunStatus::Failed);
            return Result<ReconciliationResult>::err(r.error());
        }
    }

    bool success = true;

    // ORPHAN_ACCOUNT: in target but not in HR
    for (const auto& [id, sysUser] : targetSystem) {
        if (hrSource.find(id) == hrSource.end()) {
            ++result.orphanCount;
            std::string hash = computeHash(id, ViolationType::OrphanAccount, orphanSeverity_);

            if (mode == RunMode::DryRun) {
                SPDLOG_INFO("[DRY-RUN] Orphan Account: {} (ID: {})", sysUser.name, id);
            } else {
                ViolationRecord vr{ id, ViolationType::OrphanAccount, orphanSeverity_ };
                if (auto r = store_.bulkInsertViolation(vr, result.runId, hash); r.hasError()) {
                    SPDLOG_ERROR("Failed to log orphan violation for {}: {}", id, r.error().message);
                    success = false;
                    break;
                }
                SPDLOG_WARN("Orphan Account Detected: {} (ID: {})", sysUser.name, id);
            }
        }
    }

    // MISSING_ACCOUNT: in HR but not in target
    if (success) {
        for (const auto& [id, hrUser] : hrSource) {
            if (targetSystem.find(id) == targetSystem.end()) {
                ++result.missingCount;
                std::string hash = computeHash(id, ViolationType::MissingAccount, missingSeverity_);

                if (mode == RunMode::DryRun) {
                    SPDLOG_INFO("[DRY-RUN] Missing Account: {} (ID: {})", hrUser.name, id);
                } else {
                    ViolationRecord vr{ id, ViolationType::MissingAccount, missingSeverity_ };
                    if (auto r = store_.bulkInsertViolation(vr, result.runId, hash); r.hasError()) {
                        SPDLOG_ERROR("Failed to log missing violation for {}: {}", id, r.error().message);
                        success = false;
                        break;
                    }
                }
            }
        }
    }

    if (mode != RunMode::DryRun) {
        if (auto r = store_.finalizeBulkInsert(); r.hasError()) {
            SPDLOG_ERROR("Failed to finalize bulk insert: {}", r.error().message);
            success = false;
        }
    }

    if (!success) {
        if (mode != RunMode::DryRun) {
            store_.rollbackTransaction();
            store_.completeRun(result.runId, RunStatus::Failed);
        }
        result.success = false;
        return Result<ReconciliationResult>::ok(result);
    }

    if (mode != RunMode::DryRun) {
        if (auto r = store_.commitTransaction(); r.hasError()) {
            store_.rollbackTransaction();
            store_.completeRun(result.runId, RunStatus::Failed);
            return Result<ReconciliationResult>::err(r.error());
        }
        if (auto r = store_.completeRun(result.runId, RunStatus::Success); r.hasError()) {
            return Result<ReconciliationResult>::err(r.error());
        }
    }

    result.success = true;
    SPDLOG_INFO("Run {} completed: {} orphans, {} missing", result.runId, result.orphanCount, result.missingCount);
    return Result<ReconciliationResult>::ok(result);
}