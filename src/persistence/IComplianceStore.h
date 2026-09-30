#pragma once
#include "core/Result.h"
#include "core/Policy.h"
#include "persistence/IViolationStore.h"
#include <string>
#include <vector>
#include <optional>

// Read-side view joining immutable evidence with mutable workflow status.
struct FindingView {
    int findingId = 0;
    std::string runId;
    std::string userId;
    ViolationType type = ViolationType::OrphanAccount;
    Severity severity = Severity::Medium;
    std::string detectedAt;
    FindingStatus status = FindingStatus::Open;
    std::string integrityHash;
};

struct RunInfo {
    std::string runId;
    std::string sourceSystem;
    std::string targetSystem;
    std::string startedAt;
    std::string completedAt;
    RunStatus status = RunStatus::Running;
    int totalViolations = 0;
};

// I9/I10: reads go through a dedicated query interface so the write path
// (IViolationStore) and read path can evolve independently.
class IComplianceQueryStore {
public:
    virtual ~IComplianceQueryStore() = default;

    virtual Result<bool> runExists(const std::string& runId) = 0;
    virtual Result<RunInfo> getRun(const std::string& runId) = 0;
    virtual Result<std::vector<FindingView>> queryFindings(
        const std::string& runId, int limit, int offset) = 0;
    virtual Result<int> countFindings(const std::string& runId) = 0;
};
