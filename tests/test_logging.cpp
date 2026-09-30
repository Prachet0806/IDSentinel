#include <catch2/catch_test_macros.hpp>
#include <core/Logging.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <filesystem>
#include <fstream>
#include <string>

namespace {
std::string readWholeFile(const std::filesystem::path& p) {
    std::ifstream f(p);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
}

TEST_CASE("Logging - toSpdlogLevel mapping", "[logging]") {
    REQUIRE(toSpdlogLevel(LogLevel::Trace) == spdlog::level::trace);
    REQUIRE(toSpdlogLevel(LogLevel::Debug) == spdlog::level::debug);
    REQUIRE(toSpdlogLevel(LogLevel::Info) == spdlog::level::info);
    REQUIRE(toSpdlogLevel(LogLevel::Warn) == spdlog::level::warn);
    REQUIRE(toSpdlogLevel(LogLevel::Error) == spdlog::level::err);
    REQUIRE(toSpdlogLevel(LogLevel::Critical) == spdlog::level::critical);
}

TEST_CASE("Logging - JSON output is valid JSON with escaped message", "[logging]") {
    auto logPath = std::filesystem::temp_directory_path() / "idsentinel_test_json.log";
    std::error_code ec;
    std::filesystem::remove(logPath, ec);

    initLogging(LogFormat::Json, LogLevel::Debug, logPath, 10, 2, false);
    const std::string tricky = "quote:\" backslash:\\ newline:\n tab:\t";
    SPDLOG_INFO("{}", tricky);
    spdlog::default_logger()->flush();

    std::string content = readWholeFile(logPath);
    REQUIRE(!content.empty());
    // Every line must parse as JSON and the message must round-trip exactly.
    bool found = false;
    std::stringstream ss(content);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        auto j = nlohmann::json::parse(line); // throws on invalid JSON
        REQUIRE(j.contains("timestamp"));
        REQUIRE(j.contains("level"));
        REQUIRE(j.contains("logger"));
        REQUIRE(j.contains("message"));
        if (j["message"] == tricky) found = true;
    }
    REQUIRE(found);

    std::filesystem::remove(logPath, ec);
}

TEST_CASE("Logging - file sink is opt-in", "[logging]") {
    auto logPath = std::filesystem::temp_directory_path() / "idsentinel_test_optin.log";
    std::error_code ec;
    std::filesystem::remove(logPath, ec);

    // No file path: console only, nothing created on disk.
    initLogging(LogFormat::Text, LogLevel::Info, std::nullopt);
    SPDLOG_INFO("opt-in check");
    REQUIRE(!std::filesystem::exists(logPath));

    // Explicit path: file created.
    initLogging(LogFormat::Text, LogLevel::Info, logPath, 10, 2, false);
    SPDLOG_INFO("opt-in check");
    spdlog::default_logger()->flush();
    REQUIRE(std::filesystem::exists(logPath));

    std::filesystem::remove(logPath, ec);
}
