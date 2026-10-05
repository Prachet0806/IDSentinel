#include "Reconciler.h"
#include "config/Config.h"
#include <spdlog/spdlog.h>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <thread>
#include <vector>
#include <limits>
#include <stdexcept>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <algorithm>

namespace {
// EVP_DecodeBlock takes an int length; base64 keys are tiny, so reject
// anything that does not fit rather than implicitly narrowing size_t.
int checkedKeyLength(std::size_t n) {
    if (n > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        throw std::length_error("HMAC key encoding too large");
    }
    return static_cast<int>(n);
}
}

Reconciler::Reconciler(IViolationStore* store, std::string_view hmacKey, const struct PolicyConfig* policy)
    : store_(store) {
    constexpr int kHmacKeyBytes = 32;
    if (policy) {
        orphanSeverity_ = policy->orphanSeverity;
        missingSeverity_ = policy->missingSeverity;
        driftSeverity_ = policy->driftSeverity;
        SPDLOG_INFO("Policy configured: orphan={}, missing={}, drift={}",
                    toString(orphanSeverity_), toString(missingSeverity_), toString(driftSeverity_));
    } else {
        orphanSeverity_ = Severity::Critical;
        missingSeverity_ = Severity::Medium;
        driftSeverity_ = Severity::High;
        SPDLOG_WARN("No policy configured, using defaults: orphan=CRITICAL, missing=MEDIUM, drift=HIGH");
    }

    if (!hmacKey.empty()) {
        // Decode base64 (EVP_DecodeBlock does not discount '=' padding)
        std::string decoded;
        decoded.resize(hmacKey.size());
        int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL C API requires unsigned char*
                                  reinterpret_cast<const unsigned char*>(hmacKey.data()), checkedKeyLength(hmacKey.size())); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL C API requires unsigned char*
        if (hmacKey.size() >= 1 && hmacKey.back() == '=') --len;
        if (hmacKey.size() >= 2 && hmacKey[hmacKey.size() - 2] == '=') --len;
        if (len == kHmacKeyBytes) {
            std::copy_n(reinterpret_cast<const std::uint8_t*>(decoded.data()), kHmacKeyBytes, hmacKey_.begin()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL byte buffer to uint8_t key
            hasHmacKey_ = true;
            SPDLOG_INFO("HMAC-SHA256 enabled for integrity hashes");
        } else {
            throw std::runtime_error("Invalid HMAC key: decoded length is " + std::to_string(len) + " bytes, expected 32");
        }
    } else {
        SPDLOG_WARN("No HMAC key configured, using SHA-256 without secret (not tamper-proof)");
    }
}

Reconciler::~Reconciler() {
    // Key material must not linger in memory after use.
    OPENSSL_cleanse(hmacKey_.data(), hmacKey_.size());
}

std::string Reconciler::generateRunID() {
    try {
        std::random_device rd;
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
        auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();

        constexpr uint64_t kLowMask = 0xFFFFFFFFu; // NOLINT(readability-magic-numbers): low 32 bits of timestamp
        std::seed_seq seed{
            rd(), rd(), rd(), rd(),
            static_cast<unsigned>(nanos & static_cast<decltype(nanos)>(kLowMask)),
            static_cast<unsigned>(nanos >> 32), // NOLINT(readability-magic-numbers): high 32 bits
            static_cast<unsigned>(std::hash<std::thread::id>{}(std::this_thread::get_id()))
        };

        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<uint64_t> dist;

        std::ostringstream oss;
        oss << "RUN_" << std::hex << nanos << "_" << dist(rng);
        return oss.str();
    } catch (const std::exception&) {
        return generateFallbackRunID();
    } catch (...) {
        return generateFallbackRunID();
    }
}

std::string Reconciler::generateFallbackRunID() {
    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
    const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    std::ostringstream oss;
    oss << "RUN_" << std::hex << nanos << "_fallback";
    return oss.str();
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

std::string Reconciler::hmacSha256(const std::uint8_t* key, size_t keyLen, std::string_view data) {
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
    std::string data = std::string(uid) + "|" + std::string(toString(type)) + "|" + std::string(toString(severity));

    if (hasHmacKey_) {
        return hmacSha256(hmacKey_.data(), hmacKey_.size(), data);
    }
    return sha256(data);
}

std::string Reconciler::computeHashStatic(std::string_view uid, ViolationType type, Severity severity, std::string_view hmacKey) {
    constexpr int kHmacKeyBytes = 32;
    std::string data = std::string(uid) + "|" + std::string(toString(type)) + "|" + std::string(toString(severity));

    if (!hmacKey.empty()) {
        // Decode base64
        std::string decoded;
        decoded.resize(hmacKey.size());
        int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL C API requires unsigned char*
                                  reinterpret_cast<const unsigned char*>(hmacKey.data()), checkedKeyLength(hmacKey.size())); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL C API requires unsigned char*
        if (hmacKey.size() >= 1 && hmacKey.back() == '=') --len;
        if (hmacKey.size() >= 2 && hmacKey[hmacKey.size() - 2] == '=') --len;
if (len == kHmacKeyBytes) {
        return hmacSha256(reinterpret_cast<const std::uint8_t*>(decoded.data()), kHmacKeyBytes, data); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL byte buffer to uint8_t key
    }
    }
    return sha256(data);
}

std::string Reconciler::verifyHash(std::string_view uid, ViolationType type, Severity severity, std::string_view hmacKey) {
    return computeHashStatic(uid, type, severity, hmacKey);
}

Result<Reconciler::ReconciliationResult> Reconciler::runReconciliation( // NOLINT(readability-function-cognitive-complexity): orchestration intentionally linear; helpers below keep each phase testable
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
    if (mode != RunMode::DryRun && store_) {
        if (auto r = store_->startRun(runRecord); r.hasError()) {
            return Result<ReconciliationResult>::err(r.error());
        }
        if (auto r = store_->beginTransaction(); r.hasError()) {
            // Secondary failure must not mask the primary error: log it.
            if (auto rc = store_->completeRun(result.runId, RunStatus::Failed); rc.hasError()) {
                SPDLOG_ERROR("Secondary failure marking run {} FAILED after beginTransaction error: {}",
                             result.runId, rc.error().message);
            }
            return Result<ReconciliationResult>::err(r.error());
        }
        if (auto r = store_->prepareBulkInsert(); r.hasError()) {
            if (auto rr = store_->rollbackTransaction(); rr.hasError()) {
                SPDLOG_ERROR("Secondary rollback failure for run {}: {}", result.runId, rr.error().message);
            }
            if (auto rc = store_->completeRun(result.runId, RunStatus::Failed); rc.hasError()) {
                SPDLOG_ERROR("Secondary failure marking run {} FAILED: {}", result.runId, rc.error().message);
            }
            return Result<ReconciliationResult>::err(r.error());
        }
    }

    bool success = true;

    // Deterministic order: unordered_map iteration order is unspecified, so
    // sort IDs first. Finding IDs (AUTOINCREMENT) are then stable run to run.
    std::vector<std::string> sortedTarget;
    sortedTarget.reserve(targetSystem.size());
    for (const auto& [id, _] : targetSystem) sortedTarget.emplace_back(id);
    std::sort(sortedTarget.begin(), sortedTarget.end());

    std::vector<std::string> sortedHr;
    sortedHr.reserve(hrSource.size());
    for (const auto& [id, _] : hrSource) sortedHr.emplace_back(id);
    std::sort(sortedHr.begin(), sortedHr.end());

    auto emitViolation = [&](const std::string& id, ViolationType type, Severity severity,
                             const std::string& detail) -> bool {
        std::string hash = computeHash(id, type, severity);
        if (mode == RunMode::DryRun) {
            SPDLOG_INFO("[DRY-RUN] {}: {} (ID: {})", std::string(toString(type)), detail, id);
        } else if (store_) {
            ViolationRecord vr{ id, type, severity };
            if (auto r = store_->bulkInsertViolation(vr, result.runId, hash); r.hasError()) {
                SPDLOG_ERROR("Failed to log {} violation for {}: {}",
                             std::string(toString(type)), id, r.error().message);
                return false;
            }
            SPDLOG_WARN("{} Detected: {} (ID: {})", std::string(toString(type)), detail, id);
        }
        return true;
    };

    // ORPHAN_ACCOUNT: in target but not in HR
    for (const auto& id : sortedTarget) {
        if (hrSource.find(id) == hrSource.end()) {
            ++result.orphanCount;
            if (!emitViolation(id, ViolationType::OrphanAccount, orphanSeverity_,
                               targetSystem.at(id).name)) {
                success = false;
                break;
            }
        }
    }

    // MISSING_ACCOUNT: in HR but not in target
    if (success) {
        for (const auto& id : sortedHr) {
            if (targetSystem.find(id) == targetSystem.end()) {
                ++result.missingCount;
                if (!emitViolation(id, ViolationType::MissingAccount, missingSeverity_,
                                   hrSource.at(id).name)) {
                    success = false;
                    break;
                }
            }
        }
    }

    // ATTRIBUTE_DRIFT: present in both, but name or department differs.
    if (success) {
        for (const auto& id : sortedHr) {
            auto targetIt = targetSystem.find(id);
            if (targetIt == targetSystem.end()) continue;
            const Identity& hrUser = hrSource.at(id);
            const Identity& sysUser = targetIt->second;
            if (hrUser.name != sysUser.name || hrUser.department != sysUser.department) {
                ++result.driftCount;
                std::string detail = "HR(name=" + hrUser.name + ",dept=" + hrUser.department +
                                     ") vs target(name=" + sysUser.name + ",dept=" + sysUser.department + ")";
                if (!emitViolation(id, ViolationType::AttributeDrift, driftSeverity_, detail)) {
                    success = false;
                    break;
                }
            }
        }
    }

    if (mode != RunMode::DryRun && store_) {
        if (auto r = store_->finalizeBulkInsert(); r.hasError()) {
            SPDLOG_ERROR("Failed to finalize bulk insert: {}", r.error().message);
            success = false;
        }
    }

    if (!success) {
        if (mode != RunMode::DryRun && store_) {
            if (auto rr = store_->rollbackTransaction(); rr.hasError()) {
                SPDLOG_ERROR("Secondary rollback failure for run {}: {}", result.runId, rr.error().message);
            }
            if (auto rc = store_->completeRun(result.runId, RunStatus::Failed); rc.hasError()) {
                SPDLOG_ERROR("Secondary failure marking run {} FAILED: {}", result.runId, rc.error().message);
            }
        }
        result.success = false;
        return Result<ReconciliationResult>::ok(result);
    }

    if (mode != RunMode::DryRun && store_) {
        if (auto r = store_->commitTransaction(); r.hasError()) {
            if (auto rr = store_->rollbackTransaction(); rr.hasError()) {
                SPDLOG_ERROR("Secondary rollback failure for run {}: {}", result.runId, rr.error().message);
            }
            if (auto rc = store_->completeRun(result.runId, RunStatus::Failed); rc.hasError()) {
                SPDLOG_ERROR("Secondary failure marking run {} FAILED: {}", result.runId, rc.error().message);
            }
            return Result<ReconciliationResult>::err(r.error());
        }
        if (auto r = store_->completeRun(result.runId, RunStatus::Success); r.hasError()) {
            return Result<ReconciliationResult>::err(r.error());
        }
    }

    result.success = true;
    SPDLOG_INFO("Run {} completed: {} orphans, {} missing, {} drifted",
                result.runId, result.orphanCount, result.missingCount, result.driftCount);
    return Result<ReconciliationResult>::ok(result);
}