#pragma once
#include "persistence/IViolationStore.h"
#include <core/Result.h>
#include <core/Policy.h>
#include <memory>
#include <vector>
#include <string>

struct LoggedViolation {
    std::string userId;
    ViolationType type;
    Severity severity;
    std::string runId;
    std::string hash;
};

class MockViolationStore : public IViolationStore {
public:
    MockViolationStore();
    ~MockViolationStore() override;

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

    void setFailAt(const std::string& point);
    const std::vector<LoggedViolation>& getViolations() const;
    bool wasTransactionStarted() const;
    bool wasTransactionCommitted() const;
    bool wasTransactionRolledBack() const;
    RunStatus getLastRunStatus() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};