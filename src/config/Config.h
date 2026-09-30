#pragma once
#include <string>
#include <optional>
#include <filesystem>
#include "core/Policy.h"
#include "core/Logging.h"
#include "core/Result.h"

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
    int busyTimeoutMs = 5000;
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
};

struct LoggingConfig {
    LogLevel level = LogLevel::Info;
    LogFormat format = LogFormat::Json;
    std::filesystem::path file;
    size_t maxFileSizeMb = 10;
    size_t maxFiles = 30;
    bool dailyRotation = true;

    struct RotationConfig {
        size_t maxSizeMb = 10;
        size_t maxFiles = 30;
        bool daily = true;
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
LogLevel parseLogLevel(const std::string& s);
LogFormat parseLogFormat(const std::string& s);
Severity parseSeverity(const std::string& s);
Severity parseSeverity(const std::string& s);