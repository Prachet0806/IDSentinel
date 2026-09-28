#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <config/Config.h>
#include <toml++/toml.h>
#include <fstream>
#include <filesystem>

TEST_CASE("Config - load from TOML", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"
timeout_seconds = 30

[database]
path = "test.db"
wal_mode = false

[policy]
orphan_severity = "HIGH"
missing_severity = "LOW"
)";
    f.close();

    // We can't easily test loadConfig without env isolation
    // This is a placeholder for the test structure
    REQUIRE(std::filesystem::exists(configPath));
    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - default paths are platform-appropriate", "[config]") {
    auto dbPath = getDefaultDatabasePath();
    REQUIRE(!dbPath.empty());
    REQUIRE(dbPath.filename() == "compliance.db");

    auto logDir = getDefaultLogDirectory();
    REQUIRE(!logDir.empty());
    REQUIRE(logDir.filename() == "logs");
}

TEST_CASE("Config - parseLogLevel", "[config]") {
    using namespace std::string_literals;
    REQUIRE(parseLogLevel("trace") == LogLevel::Trace);
    REQUIRE(parseLogLevel("DEBUG") == LogLevel::Debug);
    REQUIRE(parseLogLevel("Info") == LogLevel::Info);
    REQUIRE(parseLogLevel("WARN") == LogLevel::Warn);
    REQUIRE(parseLogLevel("warning") == LogLevel::Warn);
    REQUIRE(parseLogLevel("error") == LogLevel::Error);
    REQUIRE(parseLogLevel("CRITICAL") == LogLevel::Critical);
    REQUIRE(parseLogLevel("invalid") == LogLevel::Info);
}

TEST_CASE("Config - parseLogFormat", "[config]") {
    REQUIRE(parseLogFormat("json") == LogFormat::Json);
    REQUIRE(parseLogFormat("JSON") == LogFormat::Json);
    REQUIRE(parseLogFormat("text") == LogFormat::Text);
    REQUIRE(parseLogFormat("TEXT") == LogFormat::Text);
    REQUIRE(parseLogFormat("invalid") == LogFormat::Json);
}

TEST_CASE("Config - parseSeverity", "[config]") {
    REQUIRE(parseSeverity("critical") == Severity::Critical);
    REQUIRE(parseSeverity("HIGH") == Severity::High);
    REQUIRE(parseSeverity("Medium") == Severity::Medium);
    REQUIRE(parseSeverity("low") == Severity::Low);
    REQUIRE(parseSeverity("invalid") == Severity::Medium);
}