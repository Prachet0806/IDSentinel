#include "ComplianceStore.h"
#include "SchemaManager.h"
#include <spdlog/spdlog.h>
#include <sqlite3.h>
#include <array>

ComplianceStore::ComplianceStore(const std::filesystem::path& dbPath, bool walMode, int busyTimeoutMs)
    : dbPath_(dbPath), walMode_(walMode), busyTimeoutMs_(busyTimeoutMs) {}

ComplianceStore::~ComplianceStore() {
    closeDatabase();
}

Result<void> ComplianceStore::execSimple(const std::string& sql, const std::string& context) { // NOLINT(bugprone-easily-swappable-parameters): both arguments are labeled at call sites
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string err = errMsg ? errMsg : "unknown";
        sqlite3_free(errMsg);
        SPDLOG_ERROR("DB {} failed: {}", context, err);
        return Result<void>::err(Error{ "SQLITE_ERROR", context + ": " + err });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    int rc = sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        SPDLOG_ERROR("SQLite bind text failed at index {}: {}", index, sqlite3_errmsg(db_));
        return Result<void>::err(Error{ "SQLITE_BIND", "bind text index " + std::to_string(index) });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::bindInt(sqlite3_stmt* stmt, int index, int value) {
    int rc = sqlite3_bind_int(stmt, index, value);
    if (rc != SQLITE_OK) {
        SPDLOG_ERROR("SQLite bind int failed at index {}: {}", index, sqlite3_errmsg(db_));
        return Result<void>::err(Error{ "SQLITE_BIND", "bind int index " + std::to_string(index) });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::init() {
    // Legacy entry point preserved for IViolationStore compatibility.
    // This is the write path; prefer openForWrite() explicitly.
    return openForWrite();
}

Result<void> ComplianceStore::openDatabase(bool readOnly) {
    if (db_ != nullptr) {
        return Result<void>::err(Error{ "DB_ALREADY_OPEN", "database connection already open" });
    }
    const std::string dbPathStr = dbPath_.string();
    const bool isMemory = (dbPathStr == ":memory:");
    if (readOnly && isMemory) {
        return Result<void>::err(
            Error{ "DB_READONLY_REQUIRES_FILE", "read-only open requires a database file" });
    }
    if (!readOnly && !isMemory && !dbPath_.parent_path().empty()) {
        std::filesystem::create_directories(dbPath_.parent_path());
    }

    const int rc = readOnly
        ? sqlite3_open_v2(dbPathStr.c_str(), &db_, SQLITE_OPEN_READONLY, nullptr)
        : sqlite3_open(dbPathStr.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "unknown";
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        SPDLOG_ERROR("Failed to open database: {}", err);
        return Result<void>::err(Error{ "SQLITE_OPEN", err });
    }
    sqlite3_busy_timeout(db_, busyTimeoutMs_);
    return Result<void>::ok();
}

void ComplianceStore::closeDatabase() {
    if (bulkStmt_ != nullptr) {
        sqlite3_finalize(bulkStmt_);
        bulkStmt_ = nullptr;
    }
    if (db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

Result<void> ComplianceStore::openForWrite() {
    if (auto r = openDatabase(false); r.hasError()) return r;

    if (auto r = execSimple("PRAGMA foreign_keys = ON;", "Enable foreign keys"); r.hasError()) {
        closeDatabase();
        return r;
    }
    if (auto r = execSimple("PRAGMA recursive_triggers = ON;", "Enable recursive triggers"); r.hasError()) {
        closeDatabase();
        return r;
    }
    if (walMode_) {
        if (auto r = execSimple("PRAGMA journal_mode = WAL;", "Enable WAL mode"); r.hasError()) {
            closeDatabase();
            return r;
        }
    }

    // Schema is owned exclusively by SchemaManager: idempotent migrate,
    // fail-closed on legacy or future schemas. Never drops history.
    if (auto r = SchemaManager::migrate(db_); r.hasError()) {
        closeDatabase();
        return r;
    }

    // I11 (write path only): any run still marked RUNNING belongs to a
    // previous process that died without completing. It must never
    // masquerade as successful. Read-only opens must NOT perform this
    // sweep (see openReadOnly).
    if (auto r = execSimple(
            "UPDATE recon_runs SET status='ABANDONED', completed_at=CURRENT_TIMESTAMP "
            "WHERE status='RUNNING';",
            "Abandon stale runs");
        r.hasError()) {
        closeDatabase();
        return r;
    }

    int abandoned = sqlite3_changes(db_);
    if (abandoned > 0) {
        SPDLOG_WARN("Marked {} stale RUNNING run(s) as ABANDONED", abandoned);
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::openReadOnly() {
    if (auto r = openDatabase(true); r.hasError()) return r;
    if (auto r = SchemaManager::validateReadOnly(db_); r.hasError()) {
        closeDatabase();
        return r;
    }
    // No migration or stale-run sweep: a read-only open never mutates state.
    return Result<void>::ok();
}

Result<void> ComplianceStore::startRun(const RunRecord& record) {
    const char* sql = "INSERT INTO recon_runs (run_id, source_system, target_system, status) VALUES (?, ?, ?, 'RUNNING');";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<void>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }

    auto cleanup = [&] { sqlite3_finalize(stmt); };

    if (auto r = bindText(stmt, 1, record.runId); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 2, record.sourceSystem); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 3, record.targetSystem); r.hasError()) { cleanup(); return r; }

    int rc = sqlite3_step(stmt);
    cleanup();

    if (rc != SQLITE_DONE) {
        return Result<void>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }

    inTransaction_ = false;
    return Result<void>::ok();
}

Result<void> ComplianceStore::completeRun(const std::string& runId, RunStatus status) {
    const char* sql = "UPDATE recon_runs SET status=?, completed_at=CURRENT_TIMESTAMP WHERE run_id=?;";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<void>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }

    auto cleanup = [&] { sqlite3_finalize(stmt); };

    if (auto r = bindText(stmt, 1, std::string(toString(status))); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 2, runId); r.hasError()) { cleanup(); return r; }

    int rc = sqlite3_step(stmt);
    cleanup();

    if (rc != SQLITE_DONE) {
        return Result<void>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }
    // I10/I11: completing a nonexistent run must fail loudly, never silently.
    if (sqlite3_changes(db_) != 1) {
        return Result<void>::err(Error{ "RUN_NOT_FOUND", "No run found with run_id: " + runId });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::beginTransaction() {
    if (inTransaction_) {
        return Result<void>::err(Error{ "TRANSACTION", "Transaction already in progress" });
    }
    auto r = execSimple("BEGIN TRANSACTION;", "Begin transaction");
    if (!r.hasError()) inTransaction_ = true;
    return r;
}

Result<void> ComplianceStore::commitTransaction() {
    if (!inTransaction_) {
        return Result<void>::err(Error{ "TRANSACTION", "No transaction to commit" });
    }
    auto r = execSimple("COMMIT;", "Commit transaction");
    if (!r.hasError()) inTransaction_ = false;
    return r;
}

Result<void> ComplianceStore::rollbackTransaction() {
    if (!inTransaction_) {
        SPDLOG_WARN("Rollback called but no transaction active");
        return Result<void>::ok();
    }
    auto r = execSimple("ROLLBACK;", "Rollback transaction");
    if (!r.hasError()) inTransaction_ = false;
    return r;
}

Result<void> ComplianceStore::logViolation(const ViolationRecord& record, const std::string& runId, const std::string& integrityHash) {
    const char* sql = "INSERT INTO finding_evidence (run_id, user_id, violation_type, severity, integrity_hash, detected_at) "
                      "VALUES (?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), CURRENT_TIMESTAMP));";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<void>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }

    auto cleanup = [&] { sqlite3_finalize(stmt); };

    if (auto r = bindText(stmt, 1, runId); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 2, record.userId); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 3, std::string(toString(record.type))); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 4, std::string(toString(record.severity))); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 5, integrityHash); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 6, record.detectedAt); r.hasError()) { cleanup(); return r; }

    int rc = sqlite3_step(stmt);
    cleanup();

    if (rc != SQLITE_DONE) {
        return Result<void>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::prepareBulkInsert() {
    const char* sql = "INSERT INTO finding_evidence (run_id, user_id, violation_type, severity, integrity_hash, detected_at) "
                      "VALUES (?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), CURRENT_TIMESTAMP));";
    if (sqlite3_prepare_v2(db_, sql, -1, &bulkStmt_, nullptr) != SQLITE_OK) {
        return Result<void>::err(Error{ "SQLITE_PREPARE_BULK", sqlite3_errmsg(db_) });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::bulkInsertViolation(const ViolationRecord& record, const std::string& runId, const std::string& integrityHash) {
    if (!bulkStmt_) return Result<void>::err(Error{ "BULK_INSERT", "Bulk insert not prepared" });

    sqlite3_reset(bulkStmt_);
    sqlite3_clear_bindings(bulkStmt_);

    if (auto r = bindText(bulkStmt_, 1, runId); r.hasError()) return r;
    if (auto r = bindText(bulkStmt_, 2, record.userId); r.hasError()) return r;
    if (auto r = bindText(bulkStmt_, 3, std::string(toString(record.type))); r.hasError()) return r;
    if (auto r = bindText(bulkStmt_, 4, std::string(toString(record.severity))); r.hasError()) return r;
    if (auto r = bindText(bulkStmt_, 5, integrityHash); r.hasError()) return r;
    if (auto r = bindText(bulkStmt_, 6, record.detectedAt); r.hasError()) return r;

    int rc = sqlite3_step(bulkStmt_);
    if (rc != SQLITE_DONE) {
        return Result<void>::err(Error{ "SQLITE_EXEC_BULK", sqlite3_errmsg(db_) });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::finalizeBulkInsert() {
    if (bulkStmt_) {
        sqlite3_finalize(bulkStmt_);
        bulkStmt_ = nullptr;
    }
    return Result<void>::ok();
}

namespace {
// NULL-safe text column reader. sqlite3_column_text returns nullptr for
// SQL NULL; dereferencing it is undefined behavior.
std::string columnText(sqlite3_stmt* stmt, int index) {
    const unsigned char* text = sqlite3_column_text(stmt, index);
    return text ? reinterpret_cast<const char*>(text) : "";
}
}

Result<bool> ComplianceStore::runExists(const std::string& runId) {
    const char* sql = "SELECT 1 FROM recon_runs WHERE run_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<bool>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }
    auto cleanup = [&] { sqlite3_finalize(stmt); };
    if (auto r = bindText(stmt, 1, runId); r.hasError()) { cleanup(); return Result<bool>::err(r.error()); }

    int rc = sqlite3_step(stmt);
    cleanup();
    if (rc == SQLITE_ROW) return Result<bool>::ok(true);
    if (rc == SQLITE_DONE) return Result<bool>::ok(false);
    return Result<bool>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
}

Result<RunInfo> ComplianceStore::getRun(const std::string& runId) {
    const char* sql = "SELECT run_id, source_system, target_system, started_at,"
                      " completed_at, status, total_violations"
                      " FROM recon_runs WHERE run_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<RunInfo>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }
    auto cleanup = [&] { sqlite3_finalize(stmt); };
    if (auto r = bindText(stmt, 1, runId); r.hasError()) { cleanup(); return Result<RunInfo>::err(r.error()); }

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        cleanup();
        return Result<RunInfo>::err(Error{ "RUN_NOT_FOUND", "No run found with run_id: " + runId });
    }
    if (rc != SQLITE_ROW) {
        cleanup();
        return Result<RunInfo>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }
    RunInfo info;
    info.runId = columnText(stmt, 0);
    info.sourceSystem = columnText(stmt, 1);
    info.targetSystem = columnText(stmt, 2);
    info.startedAt = columnText(stmt, 3);
    info.completedAt = columnText(stmt, 4);
    try {
        info.status = runStatusFromString(columnText(stmt, 5));
    } catch (const std::invalid_argument& e) {
        cleanup();
        return Result<RunInfo>::err(Error{ "DATA_CORRUPT", e.what() });
    }
    info.totalViolations = sqlite3_column_int(stmt, 6); // NOLINT(readability-magic-numbers): SQL projection column index
    cleanup();
    return Result<RunInfo>::ok(std::move(info));
}

Result<std::vector<FindingView>> ComplianceStore::queryFindings(
    const std::string& runId, int limit, int offset
) {
    const char* sql =
        "SELECT e.finding_id, e.run_id, e.user_id, e.violation_type, e.severity,"
        " e.detected_at, s.status, e.integrity_hash"
        " FROM finding_evidence e"
        " JOIN finding_status s ON s.finding_id = e.finding_id"
        " WHERE e.run_id = ?"
        " ORDER BY e.finding_id LIMIT ? OFFSET ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<std::vector<FindingView>>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }
    auto cleanup = [&] { sqlite3_finalize(stmt); };
    if (auto r = bindText(stmt, 1, runId); r.hasError()) { cleanup(); return Result<std::vector<FindingView>>::err(r.error()); }
    if (auto r = bindInt(stmt, 2, limit); r.hasError()) { cleanup(); return Result<std::vector<FindingView>>::err(r.error()); }
    if (auto r = bindInt(stmt, 3, offset); r.hasError()) { cleanup(); return Result<std::vector<FindingView>>::err(r.error()); }

    std::vector<FindingView> findings;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        FindingView f;
        f.findingId = sqlite3_column_int(stmt, 0);
        f.runId = columnText(stmt, 1);
        f.userId = columnText(stmt, 2);
        try {
            f.type = violationTypeFromString(columnText(stmt, 3));
            f.severity = severityFromString(columnText(stmt, 4));
        } catch (const std::invalid_argument& e) {
            cleanup();
            return Result<std::vector<FindingView>>::err(Error{ "DATA_CORRUPT", e.what() });
        }
        f.detectedAt = columnText(stmt, 5);
        try {
            f.status = findingStatusFromString(columnText(stmt, 6)); // NOLINT(readability-magic-numbers): SQL projection column index
        } catch (const std::invalid_argument& e) {
            cleanup();
            return Result<std::vector<FindingView>>::err(Error{ "DATA_CORRUPT", e.what() });
        }
        f.integrityHash = columnText(stmt, 7); // NOLINT(readability-magic-numbers): SQL projection column index
        findings.emplace_back(std::move(f));
    }
    cleanup();
    if (rc != SQLITE_DONE) {
        return Result<std::vector<FindingView>>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }
    return Result<std::vector<FindingView>>::ok(std::move(findings));
}

Result<int> ComplianceStore::countFindings(const std::string& runId) {
    const char* sql = "SELECT COUNT(*) FROM finding_evidence WHERE run_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<int>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }
    auto cleanup = [&] { sqlite3_finalize(stmt); };
    if (auto r = bindText(stmt, 1, runId); r.hasError()) { cleanup(); return Result<int>::err(r.error()); }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        cleanup();
        return Result<int>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }
    int count = sqlite3_column_int(stmt, 0);
    cleanup();
    return Result<int>::ok(count);
}

Result<void> ComplianceStore::sealRun(const std::string& runId, int expectedCount, const std::string& signature) {
    if (!inTransaction_) return Result<void>::err(Error{"TRANSACTION", "Run sealing requires an active transaction"});
    const char* sql = "INSERT INTO run_manifests(run_id, algorithm_version, expected_count, signature) VALUES (?, 2, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return Result<void>::err(Error{"SQLITE_PREPARE", sqlite3_errmsg(db_)});
    auto a = bindText(stmt, 1, runId);
    auto b = bindInt(stmt, 2, expectedCount);
    auto c = bindText(stmt, 3, signature);
    if (a.hasError() || b.hasError() || c.hasError()) {
        sqlite3_finalize(stmt);
        return Result<void>::err(a.hasError() ? a.error() : b.hasError() ? b.error() : c.error());
    }
    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return Result<void>::err(Error{"SQLITE_EXEC", sqlite3_errmsg(db_)});
    return Result<void>::ok();
}

Result<std::optional<RunManifest>> ComplianceStore::getRunManifest(const std::string& runId) {
    const char* sql = "SELECT expected_count, signature FROM run_manifests WHERE run_id=? AND algorithm_version=2;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return Result<std::optional<RunManifest>>::err(Error{"SQLITE_PREPARE", sqlite3_errmsg(db_)});
    auto bound = bindText(stmt, 1, runId);
    if (bound.hasError()) {
        sqlite3_finalize(stmt);
        return Result<std::optional<RunManifest>>::err(bound.error());
    }
    const int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return Result<std::optional<RunManifest>>::ok(std::nullopt);
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return Result<std::optional<RunManifest>>::err(Error{"SQLITE_EXEC", sqlite3_errmsg(db_)});
    }
    RunManifest manifest{sqlite3_column_int(stmt, 0), columnText(stmt, 1)};
    sqlite3_finalize(stmt);
    return Result<std::optional<RunManifest>>::ok(std::move(manifest));
}
