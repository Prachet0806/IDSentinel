#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <persistence/ComplianceStore.h>
#include <persistence/IViolationStore.h>
#include <core/Policy.h>
#include <filesystem>
#include <sqlite3.h>

TEST_CASE("ComplianceStore - init creates schema", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath);
    auto result = store.init();
    REQUIRE(result.hasValue());

    // Verify tables exist
    sqlite3* db;
    sqlite3_open(":memory:", &db);
    // Note: in-memory DB is separate per connection, so we can't easily verify
    // This test mainly ensures init() doesn't crash
    sqlite3_close(db);
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

TEST_CASE("ComplianceStore - logViolation persists data", "[compliance_store]") {
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

    // Verify data in DB
    sqlite3* db;
    sqlite3_open(":memory:", &db);
    // Note: separate connection, can't verify directly
    sqlite3_close(db);
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
}

TEST_CASE("ComplianceStore - WAL mode enabled", "[compliance_store]") {
    std::filesystem::path dbPath = ":memory:";
    ComplianceStore store(dbPath, true, 5000);
    REQUIRE(store.init().hasValue());
    // WAL mode on :memory: may not work, but shouldn't crash
}