#include <catch2/catch_test_macros.hpp>
#include <core/Reconciler.h>
#include <core/Identity.h>
#include <core/Policy.h>
#include <core/Result.h>
#include <config/Config.h>
#include <persistence/IViolationStore.h>
#include <mocks/MockViolationStore.h>
#include <unordered_map>
#include <string>

TEST_CASE("Reconciler - orphan account detection", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(&store);

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
    Reconciler reconciler(&store);

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
    Reconciler reconciler(&store);

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
    Reconciler reconciler(&store);

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
    Reconciler reconciler(&store);

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
    Reconciler reconciler(&store);

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
    Reconciler reconciler(&store);

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "999", { "999", "Hacker", "Unk" } } };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    // Commit failure is fail-closed: run returns an error, rolls back, marks run FAILED
    REQUIRE(result.hasError());
    REQUIRE(store.wasTransactionRolledBack() == true);
    REQUIRE(store.getLastRunStatus() == RunStatus::Failed);
}

TEST_CASE("Reconciler - hash is deterministic", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(&store, ""); // No HMAC key

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "999", { "999", "Hacker", "Unk" } } };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    REQUIRE(result.hasValue());

    auto hash1 = store.getViolations()[0].hash;

    store.clearViolations();
    auto result2 = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    REQUIRE(result2.hasValue());

    auto hash2 = store.getViolations()[0].hash;
    REQUIRE(hash1 == hash2);
}

TEST_CASE("Reconciler - HMAC key produces different hash", "[reconciler]") {
    MockViolationStore store1;
    Reconciler reconciler1(&store1, ""); // No key

    MockViolationStore store2;
    std::string hmacKey = "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciBzaWduaW5nIT0="; // base64 32 bytes ("this is a test key for signing!=")
    Reconciler reconciler2(&store2, hmacKey);

    std::unordered_map<std::string, Identity> hr = { { "101", { "101", "Alice", "Eng" } } };
    std::unordered_map<std::string, Identity> system = { { "999", { "999", "Hacker", "Unk" } } };

    auto r1 = reconciler1.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    auto r2 = reconciler2.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(r1.hasValue());
    REQUIRE(r2.hasValue());
    REQUIRE(store1.getViolations()[0].hash != store2.getViolations()[0].hash);
}

TEST_CASE("Reconciler - attribute drift detection", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(&store);

    std::unordered_map<std::string, Identity> hr = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } }
    };
    std::unordered_map<std::string, Identity> system = {
        { "101", { "101", "Alice", "Engineering" } },   // identical: no finding
        { "102", { "102", "Robert", "Marketing" } }    // name+dept drift
    };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasValue());
    auto res = result.value();
    REQUIRE(res.success == true);
    REQUIRE(res.orphanCount == 0);
    REQUIRE(res.missingCount == 0);
    REQUIRE(res.driftCount == 1);
    REQUIRE(store.getViolations().size() == 1);
    REQUIRE(store.getViolations()[0].userId == "102");
    REQUIRE(store.getViolations()[0].type == ViolationType::AttributeDrift);
    REQUIRE(store.getViolations()[0].severity == Severity::High); // default drift severity
}

TEST_CASE("Reconciler - drift severity follows policy", "[reconciler]") {
    MockViolationStore store;
    PolicyConfig policy;
    policy.driftSeverity = Severity::Low;
    Reconciler reconciler(&store, "", &policy);

    std::unordered_map<std::string, Identity> hr = {
        { "101", { "101", "Alice", "Engineering" } }
    };
    std::unordered_map<std::string, Identity> system = {
        { "101", { "101", "Alice", "Support" } }
    };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    REQUIRE(result.hasValue());
    REQUIRE(result.value().driftCount == 1);
    REQUIRE(store.getViolations()[0].severity == Severity::Low);
}

TEST_CASE("Reconciler - findings emitted in deterministic ID order", "[reconciler]") {
    MockViolationStore store;
    Reconciler reconciler(&store);

    // Insert in non-sorted order; emitted findings must still be ID-sorted.
    std::unordered_map<std::string, Identity> hr = {
        { "300", { "300", "C", "X" } },
        { "100", { "100", "A", "X" } },
        { "200", { "200", "B", "X" } }
    };
    std::unordered_map<std::string, Identity> system;

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);
    REQUIRE(result.hasValue());
    REQUIRE(store.getViolations().size() == 3);
    REQUIRE(store.getViolations()[0].userId == "100");
    REQUIRE(store.getViolations()[1].userId == "200");
    REQUIRE(store.getViolations()[2].userId == "300");
}

TEST_CASE("Reconciler - policy configuration affects severity", "[reconciler]") {
    MockViolationStore store;
    PolicyConfig policy;
    policy.orphanSeverity = Severity::High;
    policy.missingSeverity = Severity::Low;
    Reconciler reconciler(&store, "", &policy);

    std::unordered_map<std::string, Identity> hr = {
        { "101", { "101", "Alice", "Engineering" } },
        { "103", { "103", "Charlie", "Marketing" } }
    };

    std::unordered_map<std::string, Identity> system = {
        { "101", { "101", "Alice", "Engineering" } },
        { "999", { "999", "Evil Hacker", "Unknown" } }
    };

    auto result = reconciler.runReconciliation(hr, system, Reconciler::RunMode::Normal);

    REQUIRE(result.hasValue());
    auto res = result.value();
    REQUIRE(res.orphanCount == 1);
    REQUIRE(res.missingCount == 1);
    REQUIRE(store.getViolations().size() == 2);
    REQUIRE(store.getViolations()[0].severity == Severity::High);  // Orphan uses High
    REQUIRE(store.getViolations()[1].severity == Severity::Low);  // Missing uses Low
}