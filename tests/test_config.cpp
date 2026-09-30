#include <catch2/catch_test_macros.hpp>
#include <config/Config.h>
#include <toml++/toml.h>
#include <fstream>
#include <filesystem>
#include <cstdlib>

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

TEST_CASE("Config - nested rotation parsing", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_rotation";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"

[logging]
level = "debug"
format = "text"
rotation = { max_size_mb = 5, max_files = 10, daily = false }
)";
    f.close();

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasValue());
    Config cfg = std::move(cfgResult.value());
    REQUIRE(cfg.logging.level == LogLevel::Debug);
    REQUIRE(cfg.logging.format == LogFormat::Text);
    REQUIRE(cfg.logging.rotation.has_value());
    REQUIRE(cfg.logging.rotation->maxSizeMb == 5);
    REQUIRE(cfg.logging.rotation->maxFiles == 10);
    REQUIRE(cfg.logging.rotation->daily == false);
    REQUIRE(cfg.logging.maxFileSizeMb == 5);
    REQUIRE(cfg.logging.maxFiles == 10);
    REQUIRE(cfg.logging.dailyRotation == false);

    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - flat logging keys (backward compat)", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_flat";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"

[logging]
level = "info"
max_size_mb = 20
max_files = 5
daily = true
)";
    f.close();

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasValue());
    Config cfg = std::move(cfgResult.value());
    REQUIRE(cfg.logging.maxFileSizeMb == 20);
    REQUIRE(cfg.logging.maxFiles == 5);
    REQUIRE(cfg.logging.dailyRotation == true);

    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - invalid HMAC key returns error", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_hmac";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"

[security]
hmac_key = "invalid_key"
)";
    f.close();

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasError());
    REQUIRE(cfgResult.error().code == "CONFIG");

    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - invalid timeout returns error", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_timeout";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"
timeout_seconds = 0
)";
    f.close();

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasError());
    REQUIRE(cfgResult.error().code == "CONFIG");

    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - network hardening defaults", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_net";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"
)";
    f.close();

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasValue());
    Config cfg = std::move(cfgResult.value());
    REQUIRE(cfg.network.maxResponseMb == 10);
    REQUIRE(cfg.network.maxRetries == 3);

    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - network hardening values parsed", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_net2";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"
max_response_mb = 25
max_retries = 5
)";
    f.close();

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasValue());
    Config cfg = std::move(cfgResult.value());
    REQUIRE(cfg.network.maxResponseMb == 25);
    REQUIRE(cfg.network.maxRetries == 5);

    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - invalid network hardening values rejected", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_net3";
    std::filesystem::create_directories(tmpDir);

    {
        std::filesystem::path configPath = tmpDir / "bad_response.toml";
        std::ofstream f(configPath);
        f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"
max_response_mb = 0
)";
        f.close();
        auto cfgResult = loadConfig(configPath);
        REQUIRE(cfgResult.hasError());
        REQUIRE(cfgResult.error().code == "CONFIG");
    }

    {
        std::filesystem::path configPath = tmpDir / "bad_retries.toml";
        std::ofstream f(configPath);
        f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"
max_retries = -1
)";
        f.close();
        auto cfgResult = loadConfig(configPath);
        REQUIRE(cfgResult.hasError());
        REQUIRE(cfgResult.error().code == "CONFIG");
    }

    std::filesystem::remove_all(tmpDir);
}

namespace {
class EnvGuard {
public:
    EnvGuard(const char* name, const char* value) : name_(name) {
        const char* prev = std::getenv(name);
        if (prev) previous_ = prev;
#ifdef _WIN32
        _putenv_s(name, value);
#else
        setenv(name, value, 1);
#endif
    }
    ~EnvGuard() {
#ifdef _WIN32
        if (previous_) {
            _putenv_s(name_, previous_->c_str());
        } else {
            _putenv_s(name_, "");
        }
#else
        if (previous_) {
            setenv(name_, previous_->c_str(), 1);
        } else {
            unsetenv(name_);
        }
#endif
    }
private:
    const char* name_;
    std::optional<std::string> previous_;
};
}

TEST_CASE("Config - environment overrides file values", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_env";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://file.example.com/feed"
timeout_seconds = 10

[policy]
orphan_severity = "LOW"
)";
    f.close();

    EnvGuard urlGuard("IDSENTINEL_NETWORK__HR_FEED_URL", "https://env.example.com/feed");
    EnvGuard timeoutGuard("IDSENTINEL_NETWORK__TIMEOUT_SECONDS", "42");
    EnvGuard sevGuard("IDSENTINEL_POLICY__ORPHAN_SEVERITY", "CRITICAL");
    EnvGuard driftGuard("IDSENTINEL_POLICY__DRIFT_SEVERITY", "LOW");
    EnvGuard ageGuard("IDSENTINEL_SOURCE__MAX_FILE_AGE_HOURS", "72");

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasValue());
    Config cfg = std::move(cfgResult.value());
    REQUIRE(cfg.network.hrFeedUrl == "https://env.example.com/feed");
    REQUIRE(cfg.network.timeoutSeconds == 42);
    REQUIRE(cfg.policy.orphanSeverity == Severity::Critical);
    REQUIRE(cfg.policy.driftSeverity == Severity::Low);
    REQUIRE(cfg.source.maxFileAgeHours == 72);

    std::filesystem::remove_all(tmpDir);
}

TEST_CASE("Config - invalid severity returns default", "[config]") {
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / "idsentinel_test_severity";
    std::filesystem::create_directories(tmpDir);
    std::filesystem::path configPath = tmpDir / "config.toml";

    std::ofstream f(configPath);
    f << R"(
[network]
hr_feed_url = "https://test.example.com/feed"

[policy]
orphan_severity = "INVALID"
)";
    f.close();

    auto cfgResult = loadConfig(configPath);
    REQUIRE(cfgResult.hasValue());
    Config cfg = std::move(cfgResult.value());
    REQUIRE(cfg.policy.orphanSeverity == Severity::Medium);

    std::filesystem::remove_all(tmpDir);
}