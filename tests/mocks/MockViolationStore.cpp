#include "mocks/MockViolationStore.h"
#include <core/Result.h>
#include <persistence/IViolationStore.h>

namespace {
class MockViolationStoreImpl : public IViolationStore {
public:
    std::vector<LoggedViolation> violations;
    std::string lastRunId;
    RunStatus lastRunStatus = RunStatus::Running;
    bool transactionStarted = false;
    bool transactionCommitted = false;
    bool transactionRolledBack = false;
    bool bulkPrepared = false;
    bool bulkFinalized = false;
    std::string failAt;

    Result<void> init() override { return Result<void>::ok(); }

    Result<void> startRun(const RunRecord& record) override {
        if (failAt == "startRun") return Result<void>::err(Error{ "MOCK", "startRun failed" });
        lastRunId = record.runId;
        return Result<void>::ok();
    }

    Result<void> logViolation(const ViolationRecord&, const std::string&, const std::string&) override {
        return Result<void>::ok();
    }

    Result<void> beginTransaction() override {
        if (failAt == "beginTransaction") return Result<void>::err(Error{ "MOCK", "beginTransaction failed" });
        transactionStarted = true;
        return Result<void>::ok();
    }

    Result<void> commitTransaction() override {
        if (failAt == "commit") return Result<void>::err(Error{ "MOCK", "commit failed" });
        transactionCommitted = true;
        return Result<void>::ok();
    }

    Result<void> rollbackTransaction() override {
        transactionRolledBack = true;
        return Result<void>::ok();
    }

    Result<void> completeRun(const std::string& runId, RunStatus status) override {
        if (failAt == "completeRun") return Result<void>::err(Error{ "MOCK", "completeRun failed" });
        lastRunId = runId;
        lastRunStatus = status;
        return Result<void>::ok();
    }

    Result<void> prepareBulkInsert() override {
        if (failAt == "prepareBulk") return Result<void>::err(Error{ "MOCK", "prepareBulk failed" });
        bulkPrepared = true;
        return Result<void>::ok();
    }

    Result<void> bulkInsertViolation(const ViolationRecord& record, const std::string& runId, const std::string& hash) override {
        if (failAt == "bulkInsert") return Result<void>::err(Error{ "MOCK", "bulkInsert failed" });
        violations.push_back({ record.userId, record.type, record.severity, runId, hash });
        return Result<void>::ok();
    }

    Result<void> finalizeBulkInsert() override {
        bulkFinalized = true;
        return Result<void>::ok();
    }
};
}

MockViolationStore::MockViolationStore() : pImpl(std::make_unique<MockViolationStoreImpl>()) {}
MockViolationStore::~MockViolationStore() = default;

Result<void> MockViolationStore::init() { return pImpl->init(); }
Result<void> MockViolationStore::startRun(const RunRecord& r) { return pImpl->startRun(r); }
Result<void> MockViolationStore::logViolation(const ViolationRecord& r, const std::string& runId, const std::string& hash) { return pImpl->logViolation(r, runId, hash); }
Result<void> MockViolationStore::beginTransaction() { return pImpl->beginTransaction(); }
Result<void> MockViolationStore::commitTransaction() { return pImpl->commitTransaction(); }
Result<void> MockViolationStore::rollbackTransaction() { return pImpl->rollbackTransaction(); }
Result<void> MockViolationStore::completeRun(const std::string& runId, RunStatus status) { return pImpl->completeRun(runId, status); }
Result<void> MockViolationStore::prepareBulkInsert() { return pImpl->prepareBulkInsert(); }
Result<void> MockViolationStore::bulkInsertViolation(const ViolationRecord& r, const std::string& runId, const std::string& hash) { return pImpl->bulkInsertViolation(r, runId, hash); }
Result<void> MockViolationStore::finalizeBulkInsert() { return pImpl->finalizeBulkInsert(); }

void MockViolationStore::setFailAt(const std::string& point) { pImpl->failAt = point; }
const std::vector<MockViolationStore::LoggedViolation>& MockViolationStore::getViolations() const { return pImpl->violations; }
bool MockViolationStore::wasTransactionStarted() const { return pImpl->transactionStarted; }
bool MockViolationStore::wasTransactionCommitted() const { return pImpl->transactionCommitted; }
bool MockViolationStore::wasTransactionRolledBack() const { return pImpl->transactionRolledBack; }
RunStatus MockViolationStore::getLastRunStatus() const { return pImpl->lastRunStatus; }