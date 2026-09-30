#include <catch2/catch_test_macros.hpp>
#include <cli/CLI.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

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
    REQUIRE(runKeygen(opts) == 0);
    opts.keyFormat = "hex";
    REQUIRE(runKeygen(opts) == 0);
}
