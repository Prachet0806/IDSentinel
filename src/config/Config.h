#pragma once
#include <string>
#include <optional>
#include <filesystem>
#include <toml++/toml.h>
#include "core/Policy.h"
#include "core/Logging.h"
#include "core/Result.h"

inline constexpr int kDefaultBusyTimeoutMs = 5000; // SQLite busy wait in milliseconds.
inline constexpr size_t kDefaultLogRetentionFiles = 30;

struct NetworkConfig {
    std::string hrFeedUrl = "https://gist.githubusercontent.com/dummy/raw/hr_feed.csv";
    int timeoutSeconds = 10;
    std::string caBundlePath;
    int maxResponseMb = 10;
    int maxRetries = 3;
};

struct DatabaseConfig {
    std::filesystem::path path;
    bool walMode = true;
    int busyTimeoutMs = kDefaultBusyTimeoutMs;
};

struct PolicyConfig {
    Severity orphanSeverity = Severity::Critical;
    Severity missingSeverity = Severity::Medium;
    Severity driftSeverity = Severity::High;
};

struct SourceConfig {
    // Maximum age (hours) of a file-backed source before it is rejected.
    // 0 = freshness check disabled.
    int maxFileAgeHours = 0;
    std::filesystem::path hrFallbackPath;
    std::filesystem::path targetPath;
};

struct LoggingConfig {
    LogLevel level = LogLevel::Info;
    LogFormat format = LogFormat::Json;
    std::filesystem::path file;
    size_t maxFileSizeMb = 10;
    size_t maxFiles = kDefaultLogRetentionFiles;
    bool dailyRotation = false;

    struct RotationConfig {
        size_t maxSizeMb = 10;
        size_t maxFiles = kDefaultLogRetentionFiles;
        bool daily = false;
    };
    std::optional<RotationConfig> rotation;
};

struct SecurityConfig {
    std::string hmacKey;
};

struct Config {
    NetworkConfig network;
    DatabaseConfig database;
    PolicyConfig policy;
    LoggingConfig logging;
    SecurityConfig security;
    SourceConfig source;
};

Result<Config> loadConfig(const std::optional<std::filesystem::path>& explicitPath = std::nullopt);
std::filesystem::path getDefaultConfigPath();
std::filesystem::path getDefaultDatabasePath();
std::filesystem::path getDefaultLogDirectory();

// Config parsing functions (for testing)
Result<LogLevel> parseLogLevel(const std::string& s);
Result<LogFormat> parseLogFormat(const std::string& s);
Result<Severity> parseSeverity(const std::string& s);
Result<void> parseConfig(const toml::table& tbl, Config& cfg);
