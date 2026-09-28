#include "ComplianceStore.h"
#include <spdlog/spdlog.h>
#include <sqlite3.h>
#include <array>

ComplianceStore::ComplianceStore(const std::filesystem::path& dbPath, bool walMode, int busyTimeoutMs)
    : dbPath_(dbPath), walMode_(walMode), busyTimeoutMs_(busyTimeoutMs) {}

ComplianceStore::~ComplianceStore() {
    if (bulkStmt_) sqlite3_finalize(bulkStmt_);
    if (db_) sqlite3_close(db_);
}

Result<void> ComplianceStore::execSimple(const std::string& sql, const std::string& context) {
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
    std::filesystem::create_directories(dbPath_.parent_path());

    if (sqlite3_open(dbPath_.string().c_str(), &db_) != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "unknown";
        SPDLOG_ERROR("Failed to open database: {}", err);
        return Result<void>::err(Error{ "SQLITE_OPEN", err });
    }

    if (auto r = execSimple("PRAGMA foreign_keys = ON;", "Enable foreign keys"); r.hasError()) return r;
    if (walMode_) {
        if (auto r = execSimple("PRAGMA journal_mode = WAL;", "Enable WAL mode"); r.hasError()) return r;
    }
    if (auto r = execSimple("PRAGMA busy_timeout = " + std::to_string(busyTimeoutMs_) + ";", "Set busy timeout"); r.hasError()) return r;

    const char* schema = R"SQL(
        CREATE TABLE IF NOT EXISTS recon_runs (
            run_id TEXT PRIMARY KEY,
            source_system TEXT NOT NULL,
            target_system TEXT NOT NULL,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            status TEXT CHECK(status IN ('RUNNING','SUCCESS','FAILED')),
            total_violations INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS compliance_findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'OPEN',
            integrity_hash TEXT,
            FOREIGN KEY(run_id) REFERENCES recon_runs(run_id)
        );

        CREATE TABLE IF NOT EXISTS violation_history (
            user_id TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            first_detected TIMESTAMP,
            last_detected TIMESTAMP,
            occurrence_count INTEGER DEFAULT 1,
            PRIMARY KEY (user_id, violation_type)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_run ON compliance_findings(run_id);
        CREATE INDEX IF NOT EXISTS idx_findings_user ON compliance_findings(user_id);
        CREATE INDEX IF NOT EXISTS idx_findings_type ON compliance_findings(violation_type);

        CREATE TRIGGER IF NOT EXISTS trg_update_history
        AFTER INSERT ON compliance_findings
        BEGIN
            UPDATE violation_history
            SET last_detected = NEW.detected_at,
                occurrence_count = occurrence_count + 1
            WHERE user_id = NEW.user_id
              AND violation_type = NEW.violation_type;

            INSERT OR IGNORE INTO violation_history
                (user_id, violation_type, first_detected, last_detected)
            VALUES
                (NEW.user_id, NEW.violation_type,
                 NEW.detected_at, NEW.detected_at);
        END;

        CREATE TRIGGER IF NOT EXISTS trg_update_run_summary
        AFTER INSERT ON compliance_findings
        BEGIN
            UPDATE recon_runs
            SET total_violations = total_violations + 1
            WHERE run_id = NEW.run_id;
        END;
    )SQL";

    return execSimple(schema, "Apply schema");
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

    if (auto r = bindText(stmt, 1, toString(status)); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 2, runId); r.hasError()) { cleanup(); return r; }

    int rc = sqlite3_step(stmt);
    cleanup();

    if (rc != SQLITE_DONE) {
        return Result<void>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
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
    const char* sql = "INSERT INTO compliance_findings (run_id, user_id, violation_type, severity, integrity_hash) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<void>::err(Error{ "SQLITE_PREPARE", sqlite3_errmsg(db_) });
    }

    auto cleanup = [&] { sqlite3_finalize(stmt); };

    if (auto r = bindText(stmt, 1, runId); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 2, record.userId); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 3, toString(record.type)); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 4, toString(record.severity)); r.hasError()) { cleanup(); return r; }
    if (auto r = bindText(stmt, 5, integrityHash); r.hasError()) { cleanup(); return r; }

    int rc = sqlite3_step(stmt);
    cleanup();

    if (rc != SQLITE_DONE) {
        return Result<void>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::prepareBulkInsert() {
    const char* sql = "INSERT INTO compliance_findings (run_id, user_id, violation_type, severity, integrity_hash) VALUES (?, ?, ?, ?, ?);";
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
    if (auto r = bindText(bulkStmt_, 3, toString(record.type)); r.hasError()) return r;
    if (auto r = bindText(bulkStmt_, 4, toString(record.severity)); r.hasError()) return r;
    if (auto r = bindText(bulkStmt_, 5, integrityHash); r.hasError()) return r;

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