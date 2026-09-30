#include "mocks/MockViolationStore.h"
#include <core/Result.h>
#include <persistence/IViolationStore.h>

MockViolationStore::MockViolationStore() = default;

Result<void> MockViolationStore::init() { return Result<void>::ok(); }

Result<void> MockViolationStore::startRun(const RunRecord& record) {
    if (failAt_ == "startRun") return Result<void>::err(Error{ "MOCK", "startRun failed" });
    lastRunId_ = record.runId;
    return Result<void>::ok();
}

Result<void> MockViolationStore::logViolation(const ViolationRecord&, const std::string&, const std::string&) {
    return Result<void>::ok();
}

Result<void> MockViolationStore::beginTransaction() {
    if (failAt_ == "beginTransaction") return Result<void>::err(Error{ "MOCK", "beginTransaction failed" });
    transactionStarted_ = true;
    return Result<void>::ok();
}

Result<void> MockViolationStore::commitTransaction() {
    if (failAt_ == "commit") return Result<void>::err(Error{ "MOCK", "commit failed" });
    transactionCommitted_ = true;
    return Result<void>::ok();
}

Result<void> MockViolationStore::rollbackTransaction() {
    transactionRolledBack_ = true;
    return Result<void>::ok();
}

Result<void> MockViolationStore::completeRun(const std::string& runId, RunStatus status) {
    if (failAt_ == "completeRun") return Result<void>::err(Error{ "MOCK", "completeRun failed" });
    lastRunId_ = runId;
    lastRunStatus_ = status;
    return Result<void>::ok();
}

Result<void> MockViolationStore::prepareBulkInsert() {
    if (failAt_ == "prepareBulk") return Result<void>::err(Error{ "MOCK", "prepareBulk failed" });
    bulkPrepared_ = true;
    return Result<void>::ok();
}

Result<void> MockViolationStore::bulkInsertViolation(const ViolationRecord& record, const std::string& runId, const std::string& hash) {
    if (failAt_ == "bulkInsert") return Result<void>::err(Error{ "MOCK", "bulkInsert failed" });
    violations_.push_back({ record.userId, record.type, record.severity, runId, hash });
    return Result<void>::ok();
}

Result<void> MockViolationStore::finalizeBulkInsert() {
    bulkFinalized_ = true;
    return Result<void>::ok();
}

Result<bool> MockViolationStore::runExists(const std::string& runId) {
    return Result<bool>::ok(runId == lastRunId_);
}

Result<RunInfo> MockViolationStore::getRun(const std::string& runId) {
    if (runId != lastRunId_) {
        return Result<RunInfo>::err(Error{ "RUN_NOT_FOUND", "No run found with run_id: " + runId });
    }
    RunInfo info;
    info.runId = lastRunId_;
    info.status = lastRunStatus_;
    info.totalViolations = static_cast<int>(violations_.size());
    return Result<RunInfo>::ok(std::move(info));
}

Result<std::vector<FindingView>> MockViolationStore::queryFindings(
    const std::string& runId, int limit, int offset
) {
    std::vector<FindingView> out;
    if (runId != lastRunId_) return Result<std::vector<FindingView>>::ok(std::move(out));
    int skipped = 0;
    for (const auto& v : violations_) {
        if (skipped < offset) { ++skipped; continue; }
        if (static_cast<int>(out.size()) >= limit) break;
        FindingView f;
        f.userId = v.userId;
        f.type = v.type;
        f.severity = v.severity;
        f.runId = v.runId;
        f.integrityHash = v.hash;
        out.push_back(std::move(f));
    }
    return Result<std::vector<FindingView>>::ok(std::move(out));
}

Result<int> MockViolationStore::countFindings(const std::string& runId) {
    if (runId != lastRunId_) return Result<int>::ok(0);
    return Result<int>::ok(static_cast<int>(violations_.size()));
}

void MockViolationStore::setFailAt(const std::string& point) { failAt_ = point; }
const std::vector<LoggedViolation>& MockViolationStore::getViolations() const { return violations_; }
void MockViolationStore::clearViolations() { violations_.clear(); }
bool MockViolationStore::wasTransactionStarted() const { return transactionStarted_; }
bool MockViolationStore::wasTransactionCommitted() const { return transactionCommitted_; }
bool MockViolationStore::wasTransactionRolledBack() const { return transactionRolledBack_; }
RunStatus MockViolationStore::getLastRunStatus() const { return lastRunStatus_; }