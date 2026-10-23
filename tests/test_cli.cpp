#include <catch2/catch_test_macros.hpp>
#include <cli/CLI.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <chrono>
#include <connectors/NetworkConnector.h>

namespace {
Result<CLIOptions> runParse(std::vector<std::string> args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& a : args) argv.push_back(a.data());
    return parseCLI(static_cast<int>(argv.size()), argv.data());
}
}

TEST_CASE("CLI - no subcommand defaults to reconcile", "[cli]") {
    auto result = runParse({"idsentinel"});
    REQUIRE(result.hasValue());
    REQUIRE(result.value().command == CLIOptions::Command::Reconcile);
    REQUIRE(result.value().dryRun == false);
}

TEST_CASE("CLI - reconcile flags", "[cli]") {
    auto result = runParse({"idsentinel", "reconcile", "--dry-run", "--allow-empty-target"});
    REQUIRE(result.hasValue());
    REQUIRE(result.value().command == CLIOptions::Command::Reconcile);
    REQUIRE(result.value().dryRun == true);
    REQUIRE(result.value().allowEmptyTarget == true);
}

TEST_CASE("CLI - inspect requires run-id", "[cli]") {
    auto missing = runParse({"idsentinel", "inspect"});
    REQUIRE(missing.hasError());

    auto ok = runParse({"idsentinel", "inspect", "--run-id", "RUN_1"});
    REQUIRE(ok.hasValue());
    REQUIRE(ok.value().command == CLIOptions::Command::Inspect);
    REQUIRE(ok.value().runId == "RUN_1");
    REQUIRE(ok.value().inspectFormat == "table");
    REQUIRE(ok.value().inspectLimit == 100);
    REQUIRE(ok.value().inspectOffset == 0);
}

TEST_CASE("CLI - inspect format and pagination", "[cli]") {
    auto result = runParse({"idsentinel", "inspect", "--run-id", "RUN_1",
                            "--format", "json", "--limit", "25", "--offset", "50"});
    REQUIRE(result.hasValue());
    REQUIRE(result.value().inspectFormat == "json");
    REQUIRE(result.value().inspectLimit == 25);
    REQUIRE(result.value().inspectOffset == 50);
}

TEST_CASE("CLI - inspect rejects bad format", "[cli]") {
    auto result = runParse({"idsentinel", "inspect", "--run-id", "RUN_1", "--format", "xml"});
    REQUIRE(result.hasError());
}

TEST_CASE("CLI - config and keygen subcommands", "[cli]") {
    auto cfg = runParse({"idsentinel", "config", "--validate"});
    REQUIRE(cfg.hasValue());
    REQUIRE(cfg.value().command == CLIOptions::Command::Config);
    REQUIRE(cfg.value().validateOnly == true);

    auto keygen = runParse({"idsentinel", "keygen", "--format", "hex"});
    REQUIRE(keygen.hasValue());
    REQUIRE(keygen.value().command == CLIOptions::Command::Keygen);
    REQUIRE(keygen.value().keyFormat == "hex");
}

TEST_CASE("CLI - runConfig validates malformed config", "[cli]") {
    auto tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_cli_cfg";
    std::filesystem::create_directories(tmpDir);

    CLIOptions opts;
    opts.command = CLIOptions::Command::Config;
    opts.validateOnly = true;

    {
        auto badPath = tmpDir / "bad.toml";
        std::ofstream f(badPath);
        f << "[network\nthis is not valid toml = = =\n";
        f.close();
        opts.configPath = badPath;
        REQUIRE(runConfig(opts) == 1);
    }

    {
        auto goodPath = tmpDir / "good.toml";
        std::ofstream f(goodPath);
        f << "[network]\nhr_feed_url = \"https://test.example.com/feed\"\n";
        f.close();
        opts.configPath = goodPath;
        REQUIRE(runConfig(opts) == 0);
    }

    std::error_code ec;
    std::filesystem::remove_all(tmpDir, ec);
}

TEST_CASE("CLI - runKeygen produces output-shaped exit code", "[cli]") {
    CLIOptions opts;
    opts.command = CLIOptions::Command::Keygen;
    opts.keyBits = 256;
    opts.keyFormat = "base64";
    std::ostringstream captured;
    auto* original = std::cout.rdbuf(captured.rdbuf());
    REQUIRE(runKeygen(opts) == 0);
    std::cout.rdbuf(original);
    REQUIRE(captured.str().size() == 45); // 44 Base64 chars and newline.
    opts.keyFormat = "hex";
    captured.str("");
    original = std::cout.rdbuf(captured.rdbuf());
    REQUIRE(runKeygen(opts) == 0);
    std::cout.rdbuf(original);
    REQUIRE(captured.str().size() == 65); // 64 hex chars and newline.
}

TEST_CASE("CLI dry run creates no database or log directories", "[cli][dry-run]") {
    const auto directory = std::filesystem::temp_directory_path() /
        ("idsentinel_dry_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(directory);
    const auto hrPath = directory / "hr.csv";
    const auto targetPath = directory / "target.csv";
    const auto configPath = directory / "config.toml";
    { std::ofstream hr(hrPath); hr << "101,Alice,IT\n"; }
    { std::ofstream target(targetPath); target << "101,Alice,IT\n"; }
    {
        std::ofstream config(configPath);
        config << "[network]\nhr_feed_url = \"https://127.0.0.1:1/feed.csv\"\n"
               << "timeout_seconds = 1\nmax_retries = 0\n"
               << "[database]\npath = \"" << (directory / "new_db" / "ledger.db").generic_string() << "\"\n"
               << "[source]\nhr_fallback_path = \"" << hrPath.generic_string() << "\"\n"
               << "target_path = \"" << targetPath.generic_string() << "\"\n"
               << "[logging]\nfile = \"" << (directory / "new_logs" / "audit.log").generic_string() << "\"\n";
    }
    CurlGlobal curl;
    CLIOptions options;
    options.configPath = configPath;
    options.dryRun = true;
    options.allowLocalFallback = true;
    REQUIRE(runReconcile(options) == 0);
    REQUIRE_FALSE(std::filesystem::exists(directory / "new_db"));
    REQUIRE_FALSE(std::filesystem::exists(directory / "new_logs"));
    std::error_code ec;
    std::filesystem::remove_all(directory, ec);
}
