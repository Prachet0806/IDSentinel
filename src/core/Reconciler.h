#pragma once
#include "Identity.h"
#include "Policy.h"
#include "Result.h"
#include "../persistence/IViolationStore.h"
#include <unordered_map>
#include <string>
#include <string_view>
#include <array>
#include <cstdint>

class Reconciler {
public:
    explicit Reconciler(IViolationStore* store = nullptr,
                       std::string_view hmacKey = "",
                       const struct PolicyConfig* policy = nullptr);
    ~Reconciler();

    Reconciler(const Reconciler&) = delete;
    Reconciler& operator=(const Reconciler&) = delete;

    enum class RunMode { Normal, DryRun };

    struct ReconciliationResult {
        std::string runId;
        size_t orphanCount = 0;
        size_t missingCount = 0;
        size_t driftCount = 0;
        bool success = false;
    };

    Result<ReconciliationResult> runReconciliation(
        const std::unordered_map<std::string, Identity>& hrSource,
        const std::unordered_map<std::string, Identity>& targetSystem,
        RunMode mode = RunMode::Normal
    );

    // Static method for external verification
    static std::string verifyHash(std::string_view uid, ViolationType type, Severity severity, std::string_view hmacKey);

private:
    IViolationStore* store_;
    std::array<std::uint8_t, 32> hmacKey_;
    bool hasHmacKey_ = false;

    Severity orphanSeverity_ = Severity::Critical;
    Severity missingSeverity_ = Severity::Medium;
    Severity driftSeverity_ = Severity::High;

    std::string generateRunID();
    std::string computeHash(std::string_view uid, ViolationType type, Severity severity);
    static std::string computeHashStatic(std::string_view uid, ViolationType type, Severity severity, std::string_view hmacKey);
    static std::string hmacSha256(const std::uint8_t* key, size_t keyLen, std::string_view data);
    static std::string sha256(std::string_view data);
};