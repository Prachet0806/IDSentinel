#include <catch2/catch_test_macros.hpp>
#include <persistence/ComplianceStore.h>
#include <persistence/SchemaManager.h>
#include <persistence/IViolationStore.h>
#include <persistence/IComplianceStore.h>
#include <core/Policy.h>
#include <filesystem>
#include <sqlite3.h>

namespace {
std::filesystem::path tempDb(const std::string& name) {
    auto p = std::filesystem::temp_directory_path() / ("idsentinel_schema_" + name + ".db");
    std::error_code ec;
    std::filesystem::remove(p, ec);
    std::filesystem::remove(std::filesystem::path(p.string() + "-wal"), ec);
    std::filesystem::remove(std::filesystem::path(p.string() + "-shm"), ec);
    return p;
}

void removeDb(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::remove(p, ec);
    std::filesystem::remove(std::filesystem::path(p.string() + "-wal"), ec);
    std::filesystem::remove(std::filesystem::path(p.string() + "-shm"), ec);
}

int rawCount(const std::filesystem::path& p, const char* sql) {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(p.string().c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
    int n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return n;
}

void seedRunWithFindings(const std::filesystem::path& dbPath, const std::string& runId, int n) {
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());
    REQUIRE(store.startRun(RunRecord{ runId, "HR_API", "TARGET_SYSTEM" }).hasValue());
    REQUIRE(store.beginTransaction().hasValue());
    for (int i = 0; i < n; ++i) {
        ViolationRecord vr{ "user" + std::to_string(i), ViolationType::OrphanAccount, Severity::Critical };
        REQUIRE(store.logViolation(vr, runId, "hash" + std::to_string(i)).hasValue());
    }
    REQUIRE(store.commitTransaction().hasValue());
    REQUIRE(store.completeRun(runId, RunStatus::Success).hasValue());
}
} // namespace

TEST_CASE("SchemaManager - repeated init preserves history and findings", "[schema_manager]") {
    auto dbPath = tempDb("preserves_history");
    seedRunWithFindings(dbPath, "RUN_HIST", 5);

    const int findingsBefore = rawCount(dbPath, "SELECT COUNT(*) FROM finding_evidence;");
    const int historyBefore = rawCount(dbPath, "SELECT COUNT(*) FROM violation_history;");
    REQUIRE(findingsBefore == 5);
    REQUIRE(historyBefore == 5);

    // Reopening must be a non-destructive no-op, never a reset.
    {
        ComplianceStore reopen(dbPath);
        REQUIRE(reopen.init().hasValue());
    }
    {
        ComplianceStore reopen(dbPath);
        REQUIRE(reopen.init().hasValue());
        // A second open on the same handle is rejected, never re-applied.
        REQUIRE(reopen.init().hasError());
    }

    REQUIRE(rawCount(dbPath, "SELECT COUNT(*) FROM finding_evidence;") == findingsBefore);
    REQUIRE(rawCount(dbPath, "SELECT COUNT(*) FROM violation_history;") == historyBefore);

    // New runs still work after reopen and extend history monotonically.
    seedRunWithFindings(dbPath, "RUN_HIST_2", 2);
    REQUIRE(rawCount(dbPath, "SELECT COUNT(*) FROM finding_evidence;") == 7);

    removeDb(dbPath);
}

TEST_CASE("SchemaManager - schema version is stamped", "[schema_manager]") {
    auto dbPath = tempDb("version");
    {
        ComplianceStore store(dbPath);
        REQUIRE(store.init().hasValue());
    }
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(dbPath.string().c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, "SELECT MAX(version) FROM schema_version;", -1, &stmt, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
    REQUIRE(sqlite3_column_int(stmt, 0) == SchemaManager::kCurrentVersion);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    removeDb(dbPath);
}

TEST_CASE("ComplianceStore - openReadOnly never mutates durable state", "[schema_manager]") {
    auto dbPath = tempDb("readonly");

    // Writer leaves a RUNNING run behind (simulates an active reconciliation).
    ComplianceStore writer(dbPath);
    REQUIRE(writer.init().hasValue());
    REQUIRE(writer.startRun(RunRecord{ "RUN_ACTIVE", "HR_API", "TARGET_SYSTEM" }).hasValue());
    REQUIRE(writer.beginTransaction().hasValue());
    ViolationRecord vr{ "user1", ViolationType::OrphanAccount, Severity::Critical };
    REQUIRE(writer.logViolation(vr, "RUN_ACTIVE", "hash1").hasValue());
    REQUIRE(writer.commitTransaction().hasValue());

    // Read-only observer must see RUNNING and change nothing.
    {
        ComplianceStore reader(dbPath);
        REQUIRE(reader.openReadOnly().hasValue());
        IComplianceQueryStore& query = reader;
        auto run = query.getRun("RUN_ACTIVE");
        REQUIRE(run.hasValue());
        REQUIRE(run.value().status == RunStatus::Running);
        auto count = query.countFindings("RUN_ACTIVE");
        REQUIRE(count.hasValue());
        REQUIRE(count.value() == 1);
    }

    // The stale-run sweep belongs to the write path only: still RUNNING.
    {
        ComplianceStore observer(dbPath);
        REQUIRE(observer.openReadOnly().hasValue());
        IComplianceQueryStore& query = observer;
        REQUIRE(query.getRun("RUN_ACTIVE").value().status == RunStatus::Running);
    }

    // Writer can still complete normally afterwards.
    REQUIRE(writer.completeRun("RUN_ACTIVE", RunStatus::Success).hasValue());
    removeDb(dbPath);
}

TEST_CASE("ComplianceStore - openReadOnly fails closed without a database file", "[schema_manager]") {
    auto dbPath = tempDb("missing");
    removeDb(dbPath);

    ComplianceStore reader(dbPath);
    REQUIRE(reader.openReadOnly().hasError());
    // Read path must not create a database.
    REQUIRE_FALSE(std::filesystem::exists(dbPath));

    ComplianceStore memory(":memory:");
    REQUIRE(memory.openReadOnly().hasError());
}

TEST_CASE("SchemaManager - legacy schema fails closed and preserves data", "[schema_manager]") {
    auto dbPath = tempDb("legacy");

    // Simulate a pre-split database.
    {
        sqlite3* db = nullptr;
        REQUIRE(sqlite3_open(dbPath.string().c_str(), &db) == SQLITE_OK);
        char* errMsg = nullptr;
        REQUIRE(sqlite3_exec(db,
                             "CREATE TABLE compliance_findings(id INTEGER PRIMARY KEY, note TEXT);"
                             "INSERT INTO compliance_findings(note) VALUES ('legacy-row');",
                             nullptr, nullptr, &errMsg) == SQLITE_OK);
        sqlite3_close(db);
    }

    {
        ComplianceStore store(dbPath);
        auto r = store.init();
        REQUIRE(r.hasError());
        REQUIRE(r.error().code == "SCHEMA_LEGACY");
    }

    {
        ComplianceStore reader(dbPath);
        auto r = reader.openReadOnly();
        REQUIRE(r.hasError());
        REQUIRE(r.error().code == "SCHEMA_LEGACY");
    }

    // Legacy data is untouched.
    REQUIRE(rawCount(dbPath, "SELECT COUNT(*) FROM compliance_findings;") == 1);

    removeDb(dbPath);
}
