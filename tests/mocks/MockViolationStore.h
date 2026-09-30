#pragma once
#include "persistence/IViolationStore.h"
#include "persistence/IComplianceStore.h"
#include <core/Result.h>
#include <core/Policy.h>
#include <vector>
#include <string>

struct LoggedViolation {
    std::string userId;
    ViolationType type;
    Severity severity;
    std::string runId;
    std::string hash;
};

class MockViolationStore : public IViolationStore, public IComplianceQueryStore {
public:
    MockViolationStore();
    ~MockViolationStore() override = default;

    Result<void> init() override;
    Result<void> startRun(const RunRecord&) override;
    Result<void> logViolation(const ViolationRecord&, const std::string&, const std::string&) override;
    Result<void> beginTransaction() override;
    Result<void> commitTransaction() override;
    Result<void> rollbackTransaction() override;
    Result<void> completeRun(const std::string&, RunStatus) override;
    Result<void> prepareBulkInsert() override;
    Result<void> bulkInsertViolation(const ViolationRecord&, const std::string&, const std::string&) override;
    Result<void> finalizeBulkInsert() override;

    Result<bool> runExists(const std::string& runId) override;
    Result<RunInfo> getRun(const std::string& runId) override;
    Result<std::vector<FindingView>> queryFindings(
        const std::string& runId, int limit, int offset) override;
    Result<int> countFindings(const std::string& runId) override;

    void setFailAt(const std::string& point);
    const std::vector<LoggedViolation>& getViolations() const;
    void clearViolations();
    bool wasTransactionStarted() const;
    bool wasTransactionCommitted() const;
    bool wasTransactionRolledBack() const;
    RunStatus getLastRunStatus() const;

private:
    std::vector<LoggedViolation> violations_;
    std::string lastRunId_;
    RunStatus lastRunStatus_ = RunStatus::Running;
    bool transactionStarted_ = false;
    bool transactionCommitted_ = false;
    bool transactionRolledBack_ = false;
    bool bulkPrepared_ = false;
    bool bulkFinalized_ = false;
    std::string failAt_;
};