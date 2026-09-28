#pragma once
#include "core/Result.h"
#include "core/Policy.h"
#include <string>

struct RunRecord {
    std::string runId;
    std::string sourceSystem;
    std::string targetSystem;
};

struct ViolationRecord {
    std::string userId;
    ViolationType type;
    Severity severity;
};

class IViolationStore {
public:
    virtual ~IViolationStore() = default;

    virtual Result<void> init() = 0;
    virtual Result<void> startRun(const RunRecord& record) = 0;
    virtual Result<void> logViolation(const ViolationRecord& record, const std::string& runId, const std::string& integrityHash) = 0;
    virtual Result<void> beginTransaction() = 0;
    virtual Result<void> commitTransaction() = 0;
    virtual Result<void> rollbackTransaction() = 0;
    virtual Result<void> completeRun(const std::string& runId, RunStatus status) = 0;
};