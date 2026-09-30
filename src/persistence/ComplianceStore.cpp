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
    std::string dbPathStr = dbPath_.string();
    bool isMemory = (dbPathStr == ":memory:");

    if (!isMemory && !dbPath_.parent_path().empty()) {
        std::filesystem::create_directories(dbPath_.parent_path());
    }

    if (sqlite3_open(dbPathStr.c_str(), &db_) != SQLITE_OK) {
        std::string err = db_ ? sqlite3_errmsg(db_) : "unknown";
        SPDLOG_ERROR("Failed to open database: {}", err);
        return Result<void>::err(Error{ "SQLITE_OPEN", err });
    }

    if (auto r = execSimple("PRAGMA foreign_keys = ON;", "Enable foreign keys"); r.hasError()) return r;
    if (walMode_) {
        if (auto r = execSimple("PRAGMA journal_mode = WAL;", "Enable WAL mode"); r.hasError()) return r;
    }
    if (auto r = execSimple("PRAGMA busy_timeout = " + std::to_string(busyTimeoutMs_) + ";", "Set busy timeout"); r.hasError()) return r;

    // Clean-slate schema (I8-I11): immutable evidence is separated from
    // mutable workflow status. Legacy tables from pre-split schema are
    // dropped; evidence written under the old schema is not migrated.
    const char* schema = R"SQL(
        DROP TABLE IF EXISTS compliance_findings;
        DROP TABLE IF EXISTS violation_history;
        DROP TRIGGER IF EXISTS trg_update_history;
        DROP TRIGGER IF EXISTS trg_update_run_summary;

        CREATE TABLE IF NOT EXISTS recon_runs (
            run_id TEXT PRIMARY KEY,
            source_system TEXT NOT NULL,
            target_system TEXT NOT NULL,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            status TEXT NOT NULL CHECK(status IN ('RUNNING','SUCCESS','FAILED','ABANDONED')),
            total_violations INTEGER NOT NULL DEFAULT 0
        );

        -- I8: immutable evidence. No UPDATE/DELETE allowed (see guard triggers).
        CREATE TABLE IF NOT EXISTS finding_evidence (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES recon_runs(run_id),
            user_id TEXT NOT NULL,
            violation_type TEXT NOT NULL CHECK(violation_type IN ('ORPHAN_ACCOUNT','MISSING_ACCOUNT','ATTRIBUTE_DRIFT')),
            severity TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            integrity_hash TEXT NOT NULL
        );

        -- I9: mutable workflow status, one row per finding.
        CREATE TABLE IF NOT EXISTS finding_status (
            finding_id INTEGER PRIMARY KEY REFERENCES finding_evidence(finding_id),
            status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','REVIEW','REMEDIATED')),
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT NOT NULL DEFAULT 'system'
        );

        -- I9: every status transition is auditable.
        CREATE TABLE IF NOT EXISTS finding_status_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL REFERENCES finding_evidence(finding_id),
            old_status TEXT NOT NULL,
            new_status TEXT NOT NULL CHECK(new_status IN ('OPEN','REVIEW','REMEDIATED')),
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            changed_by TEXT NOT NULL DEFAULT 'system'
        );

        CREATE TABLE IF NOT EXISTS violation_history (
            user_id TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            first_detected TIMESTAMP,
            last_detected TIMESTAMP,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (user_id, violation_type)
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_run ON finding_evidence(run_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_user ON finding_evidence(user_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_type ON finding_evidence(violation_type);
        CREATE INDEX IF NOT EXISTS idx_status_history_finding ON finding_status_history(finding_id);

        -- I8 enforcement: evidence rows can never be modified or removed.
        CREATE TRIGGER IF NOT EXISTS trg_evidence_no_update
        BEFORE UPDATE ON finding_evidence
        BEGIN
            SELECT RAISE(ABORT, 'finding_evidence is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_evidence_no_delete
        BEFORE DELETE ON finding_evidence
        BEGIN
            SELECT RAISE(ABORT, 'finding_evidence is immutable');
        END;

        -- New evidence automatically enters the OPEN workflow state.
        CREATE TRIGGER IF NOT EXISTS trg_evidence_init_status
        AFTER INSERT ON finding_evidence
        BEGIN
            INSERT INTO finding_status (finding_id, status)
            VALUES (NEW.finding_id, 'OPEN');
        END;

        -- I9 enforcement: every status change leaves an audit row.
        CREATE TRIGGER IF NOT EXISTS trg_status_audit
        AFTER UPDATE OF status ON finding_status
        BEGIN
            INSERT INTO finding_status_history (finding_id, old_status, new_status)
            VALUES (OLD.finding_id, OLD.status, NEW.status);
        END;

        CREATE TRIGGER IF NOT EXISTS trg_update_history
        AFTER INSERT ON finding_evidence
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
        AFTER INSERT ON finding_evidence
        BEGIN
            UPDATE recon_runs
            SET total_violations = total_violations + 1
            WHERE run_id = NEW.run_id;
        END;
    )SQL";

    if (auto r = execSimple(schema, "Apply schema"); r.hasError()) return r;

    // I11: any run still marked RUNNING belongs to a previous process that
    // died without completing. It must never masquerade as successful.
    if (auto r = execSimple(
            "UPDATE recon_runs SET status='ABANDONED', completed_at=CURRENT_TIMESTAMP "
            "WHERE status='RUNNING';",
            "Abandon stale runs");
        r.hasError()) return r;

    int abandoned = sqlite3_changes(db_);
    if (abandoned > 0) {
        SPDLOG_WARN("Marked {} stale RUNNING run(s) as ABANDONED", abandoned);
    }
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
    const char* sql = "INSERT INTO finding_evidence (run_id, user_id, violation_type, severity, integrity_hash) VALUES (?, ?, ?, ?, ?);";
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

    int rc = sqlite3_step(stmt);
    cleanup();

    if (rc != SQLITE_DONE) {
        return Result<void>::err(Error{ "SQLITE_EXEC", sqlite3_errmsg(db_) });
    }
    return Result<void>::ok();
}

Result<void> ComplianceStore::prepareBulkInsert() {
    const char* sql = "INSERT INTO finding_evidence (run_id, user_id, violation_type, severity, integrity_hash) VALUES (?, ?, ?, ?, ?);";
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
    info.totalViolations = sqlite3_column_int(stmt, 6);
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
            f.status = findingStatusFromString(columnText(stmt, 6));
        } catch (const std::invalid_argument& e) {
            cleanup();
            return Result<std::vector<FindingView>>::err(Error{ "DATA_CORRUPT", e.what() });
        }
        f.integrityHash = columnText(stmt, 7);
        findings.push_back(std::move(f));
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