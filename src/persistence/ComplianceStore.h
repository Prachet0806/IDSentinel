#pragma once
#include "IViolationStore.h"
#include "IComplianceStore.h"
#include <sqlite3.h>
#include <string>
#include <filesystem>

class ComplianceStore final : public IViolationStore, public IComplianceQueryStore {
public:
    explicit ComplianceStore(const std::filesystem::path& dbPath, bool walMode = true, int busyTimeoutMs = 5000);
    ~ComplianceStore() override;

    Result<void> init() override;
    Result<void> startRun(const RunRecord& record) override;
    Result<void> logViolation(const ViolationRecord& record, const std::string& runId, const std::string& integrityHash) override;
    Result<void> beginTransaction() override;
    Result<void> commitTransaction() override;
    Result<void> rollbackTransaction() override;
    Result<void> completeRun(const std::string& runId, RunStatus status) override;

    // Bulk operations for performance
    Result<void> prepareBulkInsert() override;
    Result<void> bulkInsertViolation(const ViolationRecord& record, const std::string& runId, const std::string& integrityHash) override;
    Result<void> finalizeBulkInsert() override;

    // IComplianceQueryStore (read path)
    Result<bool> runExists(const std::string& runId) override;
    Result<RunInfo> getRun(const std::string& runId) override;
    Result<std::vector<FindingView>> queryFindings(
        const std::string& runId, int limit, int offset) override;
    Result<int> countFindings(const std::string& runId) override;

private:
    sqlite3* db_ = nullptr;
    std::filesystem::path dbPath_;
    bool walMode_;
    int busyTimeoutMs_;

    sqlite3_stmt* bulkStmt_ = nullptr;
    bool inTransaction_ = false;

    Result<void> execSimple(const std::string& sql, const std::string& context);
    Result<void> bindText(sqlite3_stmt* stmt, int index, const std::string& value);
    Result<void> bindInt(sqlite3_stmt* stmt, int index, int value);
};