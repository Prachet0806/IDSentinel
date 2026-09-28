#pragma once
#include "Identity.h"
#include "Policy.h"
#include "Result.h"
#include "../persistence/IViolationStore.h"
#include <unordered_map>
#include <string>
#include <string_view>
#include <array>

class Reconciler {
public:
    explicit Reconciler(IViolationStore& store, std::string_view hmacKey = "");

    enum class RunMode { Normal, DryRun };

    struct ReconciliationResult {
        std::string runId;
        size_t orphanCount = 0;
        size_t missingCount = 0;
        bool success = false;
    };

    Result<ReconciliationResult> runReconciliation(
        const std::unordered_map<std::string, Identity>& hrSource,
        const std::unordered_map<std::string, Identity>& targetSystem,
        RunMode mode = RunMode::Normal
    );

private:
    IViolationStore& store_;
    std::array<uint8_t, 32> hmacKey_;
    bool hasHmacKey_ = false;

    Severity orphanSeverity_ = Severity::Critical;
    Severity missingSeverity_ = Severity::Medium;

    std::string generateRunID();
    std::string computeHash(std::string_view uid, ViolationType type, Severity severity);
    static std::string hmacSha256(const uint8_t* key, size_t keyLen, std::string_view data);
    static std::string sha256(std::string_view data);
};