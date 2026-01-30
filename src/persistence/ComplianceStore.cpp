#include "ComplianceStore.h"
#include <iostream>

namespace {
bool execSimple(sqlite3* db, const std::string& sql, const std::string& ctx) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[DB ERROR] " << ctx << ": " << (errMsg ? errMsg : "unknown") << "\n";
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}
}

ComplianceStore::ComplianceStore(const std::string& path)
    : db(nullptr), dbPath(path) {}

ComplianceStore::~ComplianceStore() {
    if (db) sqlite3_close(db);
}

bool ComplianceStore::init() {
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "[DB ERROR] Failed to open database\n";
        return false;
    }
    if (!execSimple(db, "PRAGMA foreign_keys = ON;", "Enable foreign keys")) {
        sqlite3_close(db);
        db = nullptr;
        return false;
    }

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

    return execSimple(db, schema, "Applying schema");
}

bool ComplianceStore::startRun(const std::string& runId,
                               const std::string& source,
                               const std::string& target) {
    const char* sql =
        "INSERT INTO recon_runs (run_id, source_system, target_system, status) "
        "VALUES (?, ?, ?, 'RUNNING');";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB ERROR] prepare startRun: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, runId.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, source.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, target.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[DB ERROR] bind startRun: " << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt);
        return false;
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[DB ERROR] execute startRun: " << sqlite3_errmsg(db) << "\n";
        return false;
    }
    return true;
}

bool ComplianceStore::completeRun(const std::string& runId,
                                  const std::string& status) {
    const char* sql =
        "UPDATE recon_runs SET status=?, completed_at=CURRENT_TIMESTAMP WHERE run_id=?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB ERROR] prepare completeRun: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, runId.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[DB ERROR] bind completeRun: " << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt);
        return false;
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[DB ERROR] execute completeRun: " << sqlite3_errmsg(db) << "\n";
        return false;
    }
    return true;
}

bool ComplianceStore::beginTransaction() {
    return execSimple(db, "BEGIN TRANSACTION;", "Begin transaction");
}

bool ComplianceStore::commitTransaction() {
    return execSimple(db, "COMMIT;", "Commit transaction");
}

void ComplianceStore::rollbackTransaction() {
    execSimple(db, "ROLLBACK;", "Rollback transaction");
}

bool ComplianceStore::logViolation(const ViolationRecord& record,
                                   const std::string& runId,
                                   const std::string& hash) {
    const char* sql =
        "INSERT INTO compliance_findings "
        "(run_id, user_id, violation_type, severity, integrity_hash) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB ERROR] prepare logViolation: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, runId.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, record.userID.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, record.type.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 4, record.severity.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 5, hash.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[DB ERROR] bind logViolation: " << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt);
        return false;
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[DB ERROR] execute logViolation: " << sqlite3_errmsg(db) << "\n";
        return false;
    }
    return true;
}
