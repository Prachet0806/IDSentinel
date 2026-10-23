#include "SchemaManager.h"
#include <spdlog/spdlog.h>

namespace {

// Full v1 schema. Every object is created idempotently; there are no DROP
// statements here by design (see class contract in SchemaManager.h).
constexpr const char* kV1Schema = R"SQL(
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

    -- I9: every status change leaves an audit row.
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

constexpr const char* kVersionTable = R"SQL(
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
)SQL";

constexpr const char* kV2Schema = R"SQL(
    CREATE TABLE IF NOT EXISTS run_manifests (
        run_id TEXT PRIMARY KEY REFERENCES recon_runs(run_id),
        algorithm_version INTEGER NOT NULL CHECK(algorithm_version = 2),
        expected_count INTEGER NOT NULL CHECK(expected_count >= 0),
        signature TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS trg_manifest_no_update
    BEFORE UPDATE ON run_manifests BEGIN SELECT RAISE(ABORT, 'run manifest is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS trg_manifest_no_delete
    BEFORE DELETE ON run_manifests BEGIN SELECT RAISE(ABORT, 'run manifest is immutable'); END;
)SQL";

} // namespace

Result<void> SchemaManager::exec(sqlite3* db, const std::string& sql, const std::string& context) { // NOLINT(bugprone-easily-swappable-parameters): SQL and context roles are labeled at every call
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string err = errMsg ? errMsg : "unknown";
        sqlite3_free(errMsg);
        SPDLOG_ERROR("Schema {} failed: {}", context, err);
        return Result<void>::err(Error{ "SCHEMA_ERROR", context + ": " + err });
    }
    return Result<void>::ok();
}

Result<bool> SchemaManager::tableExists(sqlite3* db, const std::string& name) {
    const char* sql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<bool>::err(Error{ "SCHEMA_ERROR", "prepare tableExists" });
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    bool found = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        return Result<bool>::err(Error{ "SCHEMA_ERROR", "step tableExists" });
    }
    return Result<bool>::ok(found);
}

Result<int> SchemaManager::currentVersion(sqlite3* db) {
    auto exists = tableExists(db, "schema_version");
    if (exists.hasError()) return Result<int>::err(exists.error());
    if (!exists.value()) return Result<int>::ok(0);

    const char* sql = "SELECT MAX(version) FROM schema_version;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return Result<int>::err(Error{ "SCHEMA_ERROR", "prepare currentVersion" });
    }
    int rc = sqlite3_step(stmt);
    int version = 0;
    if (rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        version = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        return Result<int>::err(Error{ "SCHEMA_ERROR", "step currentVersion" });
    }
    return Result<int>::ok(version);
}

Result<void> SchemaManager::validateReadOnly(sqlite3* db) { // NOLINT(readability-function-cognitive-complexity): ordered schema checks fail immediately
    if (db == nullptr) return Result<void>::err(Error{"SCHEMA_ERROR", "null database handle"});
    auto legacy = tableExists(db, "compliance_findings");
    if (legacy.hasError()) return Result<void>::err(legacy.error());
    if (legacy.value()) return Result<void>::err(Error{
        "SCHEMA_LEGACY", "legacy table 'compliance_findings' present: explicit migration required"});
    auto version = currentVersion(db);
    if (version.hasError()) return Result<void>::err(version.error());
    if (version.value() > kCurrentVersion) return Result<void>::err(Error{
        "SCHEMA_TOO_NEW", "database schema is newer than this binary supports"});
    for (const char* name : {"recon_runs", "finding_evidence", "finding_status"}) {
        auto exists = tableExists(db, name);
        if (exists.hasError()) return Result<void>::err(exists.error());
        if (!exists.value()) return Result<void>::err(Error{
            "SCHEMA_INCOMPLETE", std::string("required table missing: ") + name});
    }
    if (version.value() >= 2) {
        auto exists = tableExists(db, "run_manifests");
        if (exists.hasError()) return Result<void>::err(exists.error());
        if (!exists.value()) return Result<void>::err(Error{
            "SCHEMA_INCOMPLETE", "required table missing: run_manifests"});
    }
    return Result<void>::ok();
}

Result<void> SchemaManager::migrate(sqlite3* db) { // NOLINT(readability-function-cognitive-complexity): transactional migration stages fail immediately
    if (db == nullptr) {
        return Result<void>::err(Error{ "SCHEMA_ERROR", "null database handle" });
    }

    if (auto r = exec(db, "BEGIN IMMEDIATE;", "begin migration"); r.hasError()) return r;
    auto rollback = [&](const Error& e) {
        char* errMsg = nullptr;
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, &errMsg);
        sqlite3_free(errMsg);
        return Result<void>::err(e);
    };

    // Fail closed on legacy pre-split schema: evidence in the old layout
    // must never be silently dropped. The operator migrates explicitly.
    {
        auto legacy = tableExists(db, "compliance_findings");
        if (legacy.hasError()) return rollback(legacy.error());
        if (legacy.value()) {
            return rollback(Error{ "SCHEMA_LEGACY",
                "legacy table 'compliance_findings' present: explicit migration required, refusing to proceed" });
        }
    }

    {
        auto v = currentVersion(db);
        if (v.hasError()) return rollback(v.error());
        if (v.value() > kCurrentVersion) {
            return rollback(Error{ "SCHEMA_TOO_NEW",
                "database schema v" + std::to_string(v.value()) +
                " is newer than supported v" + std::to_string(kCurrentVersion)});
        }
        if (v.value() == kCurrentVersion) {
            if (auto r = exec(db, "COMMIT;", "commit migration (no-op)"); r.hasError()) {
                return rollback(Error{ "SCHEMA_ERROR", "commit failed" });
            }
            return Result<void>::ok();
        }
    }

    // Baseline v1: create everything idempotently, then stamp the version.
    if (auto r = exec(db, kV1Schema, "apply v1 schema"); r.hasError()) return rollback(r.error());
    if (auto r = exec(db, kV2Schema, "apply v2 schema"); r.hasError()) return rollback(r.error());
    if (auto r = exec(db, kVersionTable, "create schema_version"); r.hasError()) return rollback(r.error());
    if (auto r = exec(db,
            "INSERT OR REPLACE INTO schema_version(version) VALUES (" +
                std::to_string(kCurrentVersion) + ");",
            "stamp schema version");
        r.hasError()) {
        return rollback(r.error());
    }

    if (auto r = exec(db, "COMMIT;", "commit migration"); r.hasError()) {
        return rollback(Error{ "SCHEMA_ERROR", "commit failed: " + r.error().message });
    }
    SPDLOG_INFO("Database schema migrated to v{}", kCurrentVersion);
    return Result<void>::ok();
}
