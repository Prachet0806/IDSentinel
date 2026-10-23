#include <catch2/catch_test_macros.hpp>
#include <cli/CLI.h>
#include <core/Reconciler.h>
#include <persistence/ComplianceStore.h>
#include <sqlite3.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <unordered_map>

TEST_CASE("Signed verification rejects deletion of every finding", "[verification]") {
    constexpr const char* key = "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciBzaWduaW5nIT0=";
    const auto directory = std::filesystem::temp_directory_path() /
        ("idsentinel_verify_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(directory);
    const auto dbPath = directory / "ledger.db";
    const auto configPath = directory / "config.toml";
    std::string runId;
    {
        ComplianceStore store(dbPath);
        REQUIRE(store.openForWrite().hasValue());
        Reconciler reconciler(&store, key);
        std::unordered_map<std::string, Identity> hr{{"101", {"101", "Alice", "IT"}}};
        std::unordered_map<std::string, Identity> target{{"101", {"101", "Alice", "IT"}},
                                                          {"999", {"999", "Extra", "IT"}}};
        auto result = reconciler.runReconciliation(hr, target);
        REQUIRE(result.hasValue());
        REQUIRE(result.value().success);
        runId = result.value().runId;
    }
    {
        std::ofstream config(configPath);
        config << "[database]\npath = \"" << dbPath.generic_string() << "\"\n"
               << "[security]\nhmac_key = \"" << key << "\"\n";
    }
    CLIOptions options;
    options.configPath = configPath;
    options.verifyRunId = runId;
    REQUIRE(runVerify(options) == 0);

    // Simulate an administrator changing the detection timestamp after
    // removing the guard. The HMAC must cover that immutable evidence field.
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(dbPath.string().c_str(), &db) == SQLITE_OK);
    REQUIRE(sqlite3_exec(db, "DROP TRIGGER trg_evidence_no_update;"
                             "UPDATE finding_evidence SET detected_at='2000-01-01T00:00:00Z';",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
    REQUIRE(runVerify(options) == 1);

    // Removing every finding must also fail, including a false clean run.
    REQUIRE(sqlite3_exec(db, "DROP TRIGGER trg_evidence_no_delete;"
                             "DELETE FROM finding_evidence;", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(db);
    REQUIRE(runVerify(options) == 1);

    std::error_code ec;
    std::filesystem::remove_all(directory, ec);
}
