#pragma once
#include <string>
#include <optional>
#include <filesystem>
#include "core/Policy.h"

struct NetworkConfig {
    std::string hrFeedUrl = "https://gist.githubusercontent.com/dummy/raw/hr_feed.csv";
    int timeoutSeconds = 10;
    std::string caBundlePath;
};

struct DatabaseConfig {
    std::filesystem::path path;
    bool walMode = true;
    int busyTimeoutMs = 5000;
};

struct PolicyConfig {
    Severity orphanSeverity = Severity::Critical;
    Severity missingSeverity = Severity::Medium;
};

struct LoggingConfig {
    LogLevel level = LogLevel::Info;
    LogFormat format = LogFormat::Json;
    std::filesystem::path file;
    size_t maxFileSizeMb = 10;
    size_t maxFiles = 30;
    bool dailyRotation = true;
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
};

Config loadConfig(const std::optional<std::filesystem::path>& explicitPath = std::nullopt);
std::filesystem::path getDefaultConfigPath();
std::filesystem::path getDefaultDatabasePath();
std::filesystem::path getDefaultLogDirectory();