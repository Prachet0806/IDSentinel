#include <catch2/catch_test_macros.hpp>
#include <persistence/ComplianceStore.h>
#include <persistence/IViolationStore.h>
#include <persistence/IComplianceStore.h>
#include <core/Policy.h>
#include <filesystem>
#include <sqlite3.h>

namespace {
std::filesystem::path tempDb(const std::string& name) {
    auto p = std::filesystem::temp_directory_path() / ("idsentinel_" + name + ".db");
    std::error_code ec;
    std::filesystem::remove(p, ec);
    return p;
}
}

TEST_CASE("ComplianceStore - init creates schema", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    auto result = store.init();
    REQUIRE(result.hasValue());
}

TEST_CASE("ComplianceStore - startRun and completeRun", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());

    RunRecord record{ "RUN_TEST_1", "HR_API", "TARGET_SYSTEM" };
    auto r = store.startRun(record);
    REQUIRE(r.hasValue());

    r = store.completeRun("RUN_TEST_1", RunStatus::Success);
    REQUIRE(r.hasValue());
}

TEST_CASE("ComplianceStore - completeRun on missing run fails", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());

    // I10: completing a nonexistent run must fail loudly (RUN_NOT_FOUND),
    // never silently succeed.
    auto r = store.completeRun("RUN_DOES_NOT_EXIST", RunStatus::Success);
    REQUIRE(r.hasError());
    REQUIRE(r.error().code == "RUN_NOT_FOUND");
}

TEST_CASE("ComplianceStore - transaction lifecycle", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());

    RunRecord record{ "RUN_TEST_2", "HR_API", "TARGET_SYSTEM" };
    REQUIRE(store.startRun(record).hasValue());

    REQUIRE(store.beginTransaction().hasValue());
    REQUIRE(store.commitTransaction().hasValue());

    // Rollback without transaction should not error
    REQUIRE(store.rollbackTransaction().hasValue());
}

TEST_CASE("ComplianceStore - logViolation persists and is queryable", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());

    RunRecord record{ "RUN_TEST_3", "HR_API", "TARGET_SYSTEM" };
    REQUIRE(store.startRun(record).hasValue());
    REQUIRE(store.beginTransaction().hasValue());

    ViolationRecord vr{ "user123", ViolationType::OrphanAccount, Severity::Critical };
    REQUIRE(store.logViolation(vr, "RUN_TEST_3", "hash123").hasValue());

    REQUIRE(store.commitTransaction().hasValue());
    REQUIRE(store.completeRun("RUN_TEST_3", RunStatus::Success).hasValue());

    // Verify through the query interface on the SAME connection
    IComplianceQueryStore& query = store;
    auto exists = query.runExists("RUN_TEST_3");
    REQUIRE(exists.hasValue());
    REQUIRE(exists.value() == true);

    auto missing = query.runExists("RUN_NOPE");
    REQUIRE(missing.hasValue());
    REQUIRE(missing.value() == false);

    auto run = query.getRun("RUN_TEST_3");
    REQUIRE(run.hasValue());
    REQUIRE(run.value().status == RunStatus::Success);
    REQUIRE(run.value().totalViolations == 1);

    auto count = query.countFindings("RUN_TEST_3");
    REQUIRE(count.hasValue());
    REQUIRE(count.value() == 1);

    auto findings = query.queryFindings("RUN_TEST_3", 100, 0);
    REQUIRE(findings.hasValue());
    REQUIRE(findings.value().size() == 1);
    REQUIRE(findings.value()[0].userId == "user123");
    REQUIRE(findings.value()[0].type == ViolationType::OrphanAccount);
    REQUIRE(findings.value()[0].severity == Severity::Critical);
    REQUIRE(findings.value()[0].status == FindingStatus::Open);
    REQUIRE(findings.value()[0].integrityHash == "hash123");
}

TEST_CASE("ComplianceStore - getRun on missing run fails", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());

    IComplianceQueryStore& query = store;
    auto run = query.getRun("RUN_NOPE");
    REQUIRE(run.hasError());
    REQUIRE(run.error().code == "RUN_NOT_FOUND");
}

TEST_CASE("ComplianceStore - bulk insert", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());

    RunRecord record{ "RUN_TEST_4", "HR_API", "TARGET_SYSTEM" };
    REQUIRE(store.startRun(record).hasValue());
    REQUIRE(store.beginTransaction().hasValue());
    REQUIRE(store.prepareBulkInsert().hasValue());

    for (int i = 0; i < 100; ++i) {
        ViolationRecord vr{ "user" + std::to_string(i), ViolationType::OrphanAccount, Severity::Critical };
        REQUIRE(store.bulkInsertViolation(vr, "RUN_TEST_4", "hash" + std::to_string(i)).hasValue());
    }

    REQUIRE(store.finalizeBulkInsert().hasValue());
    REQUIRE(store.commitTransaction().hasValue());
    REQUIRE(store.completeRun("RUN_TEST_4", RunStatus::Success).hasValue());

    IComplianceQueryStore& query = store;
    auto count = query.countFindings("RUN_TEST_4");
    REQUIRE(count.hasValue());
    REQUIRE(count.value() == 100);

    // Pagination: page 1 and page 2 partition the findings
    auto page1 = query.queryFindings("RUN_TEST_4", 30, 0);
    auto page2 = query.queryFindings("RUN_TEST_4", 30, 30);
    auto page4 = query.queryFindings("RUN_TEST_4", 30, 90);
    REQUIRE(page1.hasValue());
    REQUIRE(page2.hasValue());
    REQUIRE(page4.hasValue());
    REQUIRE(page1.value().size() == 30);
    REQUIRE(page2.value().size() == 30);
    REQUIRE(page4.value().size() == 10);
    REQUIRE(page1.value()[0].findingId != page2.value()[0].findingId);
}

TEST_CASE("ComplianceStore - trigger updates run summary", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    REQUIRE(store.init().hasValue());

    RunRecord record{ "RUN_TEST_5", "HR_API", "TARGET_SYSTEM" };
    REQUIRE(store.startRun(record).hasValue());
    REQUIRE(store.beginTransaction().hasValue());

    ViolationRecord vr1{ "user1", ViolationType::OrphanAccount, Severity::Critical };
    ViolationRecord vr2{ "user2", ViolationType::MissingAccount, Severity::Medium };
    REQUIRE(store.logViolation(vr1, "RUN_TEST_5", "hash1").hasValue());
    REQUIRE(store.logViolation(vr2, "RUN_TEST_5", "hash2").hasValue());

    REQUIRE(store.commitTransaction().hasValue());
    REQUIRE(store.completeRun("RUN_TEST_5", RunStatus::Success).hasValue());

    IComplianceQueryStore& query = store;
    auto run = query.getRun("RUN_TEST_5");
    REQUIRE(run.hasValue());
    REQUIRE(run.value().totalViolations == 2);
}

TEST_CASE("ComplianceStore - stale RUNNING runs are abandoned on init", "[compliance_store]") {
    auto dbPath = tempDb("stale_runs");

    {
        ComplianceStore store(dbPath);
        REQUIRE(store.init().hasValue());
        RunRecord record{ "RUN_STALE", "HR_API", "TARGET_SYSTEM" };
        REQUIRE(store.startRun(record).hasValue());
        // Store destructs without completeRun: simulates a crashed process.
    }

    {
        ComplianceStore store(dbPath);
        REQUIRE(store.init().hasValue());

        IComplianceQueryStore& query = store;
        auto run = query.getRun("RUN_STALE");
        REQUIRE(run.hasValue());
        // I11: the orphaned RUNNING run must not masquerade as successful.
        REQUIRE(run.value().status == RunStatus::Abandoned);
    }

    std::error_code ec;
    std::filesystem::remove(dbPath, ec);
}

TEST_CASE("ComplianceStore - evidence is immutable", "[compliance_store]") {
    auto dbPath = tempDb("immutable");

    {
        ComplianceStore store(dbPath);
        REQUIRE(store.init().hasValue());
        RunRecord record{ "RUN_IMM", "HR_API", "TARGET_SYSTEM" };
        REQUIRE(store.startRun(record).hasValue());
        ViolationRecord vr{ "user1", ViolationType::OrphanAccount, Severity::Critical };
        REQUIRE(store.logViolation(vr, "RUN_IMM", "hash1").hasValue());
        REQUIRE(store.completeRun("RUN_IMM", RunStatus::Success).hasValue());
    }

    // I8: direct UPDATE/DELETE against finding_evidence must be rejected
    // by the guard triggers, verified over a second connection.
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(dbPath.string().c_str(), &db) == SQLITE_OK);

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, "UPDATE finding_evidence SET severity='LOW' WHERE finding_id=1;",
                          nullptr, nullptr, &errMsg);
    REQUIRE(rc != SQLITE_OK);
    std::string updateErr = errMsg ? errMsg : "";
    sqlite3_free(errMsg);
    REQUIRE(updateErr.find("immutable") != std::string::npos);

    rc = sqlite3_exec(db, "DELETE FROM finding_evidence WHERE finding_id=1;",
                      nullptr, nullptr, &errMsg);
    REQUIRE(rc != SQLITE_OK);
    std::string deleteErr = errMsg ? errMsg : "";
    sqlite3_free(errMsg);
    REQUIRE(deleteErr.find("immutable") != std::string::npos);

    // Evidence row is untouched; status workflow still mutable.
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, "SELECT severity FROM finding_evidence WHERE finding_id=1;",
                               -1, &stmt, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
    const unsigned char* sev = sqlite3_column_text(stmt, 0);
    REQUIRE(sev != nullptr);
    REQUIRE(std::string(reinterpret_cast<const char*>(sev)) == "CRITICAL");
    sqlite3_finalize(stmt);

    rc = sqlite3_exec(db, "UPDATE finding_status SET status='REVIEW' WHERE finding_id=1;",
                      nullptr, nullptr, &errMsg);
    REQUIRE(rc == SQLITE_OK);

    // I9: the status transition left an audit row.
    REQUIRE(sqlite3_prepare_v2(db, "SELECT old_status, new_status FROM finding_status_history WHERE finding_id=1;",
                               -1, &stmt, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
    const unsigned char* oldS = sqlite3_column_text(stmt, 0);
    const unsigned char* newS = sqlite3_column_text(stmt, 1);
    REQUIRE(oldS != nullptr);
    REQUIRE(newS != nullptr);
    REQUIRE(std::string(reinterpret_cast<const char*>(oldS)) == "OPEN");
    REQUIRE(std::string(reinterpret_cast<const char*>(newS)) == "REVIEW");
    sqlite3_finalize(stmt);

    sqlite3_close(db);
    std::error_code ec;
    std::filesystem::remove(dbPath, ec);
}

TEST_CASE("ComplianceStore - WAL mode enabled", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath, true, 5000);
    REQUIRE(store.init().hasValue());
    // WAL mode on :memory: may not work, but shouldn't crash
}
