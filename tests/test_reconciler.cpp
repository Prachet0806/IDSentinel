#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <core/Reconciler.h>
#include <core/Identity.h>
#include <core/Policy.h>
#include <core/Result.h>
#include <persistence/IViolationStore.h>
#include <mocks/MockViolationStore.h>
#include <unordered_map>
#include <string>

TEST_CASE("Reconciler - orphan account detection", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(store);

    std::unordered_map<std::string, Identity> hr = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } }
    };

    std::unordered_map<std::string, Identity> system = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } },
        { "999", { "999", "Evil Hacker", "Unknown" } }
    };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasValue());
    auto res = result.value();
    REQUIRE(res.orphanCount == 1);
    REQUIRE(res.missingCount == 0);
    REQUIRE(res.success == true);
    REQUIRE(store.getViolations().size() == 1);
    REQUIRE(store.getViolations()[0].userId == "999");
    REQUIRE(store.getViolations()[0].type == ViolationType::OrphanAccount);
    REQUIRE(store.getViolations()[0].severity == Severity::Critical);
    REQUIRE(store.wasTransactionStarted() == true);
    REQUIRE(store.wasTransactionCommitted() == true);
    REQUIRE(store.wasTransactionRolledBack() == false);
}

TEST_CASE("Reconciler - missing account detection", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(store);

    std::unordered_map<std::string, Identity> hr = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } },
        { "103", { "103", "Charlie", "Marketing" } }
    };

    std::unordered_map<std::string, Identity> system = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } }
    };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasValue());
    auto res = result.value();
    REQUIRE(res.orphanCount == 0);
    REQUIRE(res.missingCount == 1);
    REQUIRE(res.success == true);
    REQUIRE(store.getViolations().size() == 1);
    REQUIRE(store.getViolations()[0].userId == "103");
    REQUIRE(store.getViolations()[0].type == ViolationType::MissingAccount);
    REQUIRE(store.getViolations()[0].severity == Severity::Medium);
}

TEST_CASE("Reconciler - dry run mode", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(store);

    std::unordered_map<std::string, Identity> hr = {
        { "101", { "101", "Alice", "Engineering" } }
    };

    std::unordered_map<std::string, Identity> system = {
        { "999", { "999", "Hacker", "Unknown" } }
    };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::DryRun);

    REQUIRE(result.hasValue());
    auto res = result.value();
    REQUIRE(res.orphanCount == 1);
    REQUIRE(res.missingCount == 1);
    REQUIRE(res.success == true);
    REQUIRE(store.getViolations().empty());
    REQUIRE(!store.wasTransactionStarted());
}

TEST_CASE("Reconciler - empty HR source fails", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(store);

    std::unordered_map<std::string, Identity> hr;
    std::unordered_map<std::string, Identity> system = {
        { "101", { "101", "Alice", "Engineering" } }
    };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "VALIDATION");
}

TEST_CASE("Reconciler - startRun failure rolls back", "[reconciler]") {
    MockViolationStore store;
    store.setFailAt("startRun");
    Reconciler reconciler(store);

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "101", { "101", "Alice", "Eng" } } };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "MOCK");
    REQUIRE(!store.wasTransactionStarted());
}

TEST_CASE("Reconciler - bulkInsert failure rolls back", "[reconciler]") {
    MockViolationStore store;
    store.setFailAt("bulkInsert");
    Reconciler reconciler(store);

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "999", { "999", "Hacker", "Unk" } } };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasValue());
    auto res = result.value();
    REQUIRE(res.success == false);
    REQUIRE(store.wasTransactionRolledBack() == true);
    REQUIRE(store.getLastRunStatus() == RunStatus::Failed);
}

TEST_CASE("Reconciler - commit failure rolls back", "[reconciler]") {
    MockViolationStore store;
    store.setFailAt("commit");
    Reconciler reconciler(store);

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "999", { "999", "Hacker", "Unk" } } };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasValue());
    auto res = result.value();
    REQUIRE(res.success == false);
    REQUIRE(store.wasTransactionRolledBack() == true);
    REQUIRE(store.getLastRunStatus() == RunStatus::Failed);
}

TEST_CASE("Reconciler - hash is deterministic", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(store, ""); // No HMAC key

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "999", { "999", "Hacker", "Unk" } } };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    REQUIRE(result.hasValue());

    auto hash1 = store.getViolations()[0].hash;

    store.getViolations().clear();
    auto result2 = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    REQUIRE(result2.hasValue());

    auto hash2 = store.getViolations()[0].hash;
    REQUIRE(hash1 == hash2);
}

TEST_CASE("Reconciler - HMAC key produces different hash", "[reconciler]") {
    MockViolationStore store1;
    Reconciler reconciler1(store1, ""); // No key

    MockViolationStore store2;
    std::string hmacKey = "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciBzaWduaW5nIQ=="; // base64 32 bytes
    Reconciler reconciler2(store2, hmacKey);

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "999", { "999", "Hacker", "Unk" } } };

    auto r1 = reconciler1.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    auto r2 = reconciler2.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(r1.hasValue());
    REQUIRE(r2.hasValue());
    REQUIRE(store1.getViolations()[0].hash != store2.getViolations()[0].hash);
}