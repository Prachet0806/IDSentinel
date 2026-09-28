#pragma once
#include "IViolationStore.h"
#include <sqlite3.h>
#include <string>
#include <filesystem>

class ComplianceStore final : public IViolationStore {
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
    Result<void> prepareBulkInsert();
    Result<void> bulkInsertViolation(const ViolationRecord& record, const std::string& runId, const std::string& integrityHash);
    Result<void> finalizeBulkInsert();

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