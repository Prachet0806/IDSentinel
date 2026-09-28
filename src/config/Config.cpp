#include "Config.h"
#include <toml++/toml.h>
#include <spdlog/spdlog.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace {
std::string getEnv(const char* name) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : "";
}

template<typename T>
T getValueOr(const toml::node& node, const std::string& key, T defaultValue) {
    if (auto v = node[key]; v) return v.value_or(defaultValue);
    return defaultValue;
}

std::filesystem::path expandPath(const std::string& pathStr) {
    if (pathStr.empty()) return {};
    std::string expanded = pathStr;
    if (expanded.starts_with("~")) {
        const char* home = std::getenv("HOME");
        if (!home) home = std::getenv("USERPROFILE");
        if (home) expanded.replace(0, 1, home);
    }
    return std::filesystem::weakly_canonical(expanded);
}

std::string toUpper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

LogLevel parseLogLevel(const std::string& s) {
    auto u = toUpper(s);
    if (u == "TRACE") return LogLevel::Trace;
    if (u == "DEBUG") return LogLevel::Debug;
    if (u == "INFO") return LogLevel::Info;
    if (u == "WARN" || u == "WARNING") return LogLevel::Warn;
    if (u == "ERROR") return LogLevel::Error;
    if (u == "CRITICAL") return LogLevel::Critical;
    return LogLevel::Info;
}

LogFormat parseLogFormat(const std::string& s) {
    auto u = toUpper(s);
    if (u == "JSON") return LogFormat::Json;
    if (u == "TEXT") return LogFormat::Text;
    return LogFormat::Json;
}

Severity parseSeverity(const std::string& s) {
    auto u = toUpper(s);
    if (u == "CRITICAL") return Severity::Critical;
    if (u == "HIGH") return Severity::High;
    if (u == "MEDIUM") return Severity::Medium;
    if (u == "LOW") return Severity::Low;
    return Severity::Medium;
}

void applyEnvOverrides(Config& cfg) {
    if (auto v = getEnv("IDSENTINEL_NETWORK__HR_FEED_URL"); !v.empty()) cfg.network.hrFeedUrl = v;
    if (auto v = getEnv("IDSENTINEL_NETWORK__TIMEOUT_SECONDS"); !v.empty()) cfg.network.timeoutSeconds = std::stoi(v);
    if (auto v = getEnv("IDSENTINEL_NETWORK__CA_BUNDLE_PATH"); !v.empty()) cfg.network.caBundlePath = v;

    if (auto v = getEnv("IDSENTINEL_DATABASE__PATH"); !v.empty()) cfg.database.path = expandPath(v);
    if (auto v = getEnv("IDSENTINEL_DATABASE__WAL_MODE"); !v.empty()) cfg.database.walMode = (toUpper(v) == "TRUE");
    if (auto v = getEnv("IDSENTINEL_DATABASE__BUSY_TIMEOUT_MS"); !v.empty()) cfg.database.busyTimeoutMs = std::stoi(v);

    if (auto v = getEnv("IDSENTINEL_POLICY__ORPHAN_SEVERITY"); !v.empty()) cfg.policy.orphanSeverity = parseSeverity(v);
    if (auto v = getEnv("IDSENTINEL_POLICY__MISSING_SEVERITY"); !v.empty()) cfg.policy.missingSeverity = parseSeverity(v);

    if (auto v = getEnv("IDSENTINEL_LOGGING__LEVEL"); !v.empty()) cfg.logging.level = parseLogLevel(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__FORMAT"); !v.empty()) cfg.logging.format = parseLogFormat(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__FILE"); !v.empty()) cfg.logging.file = expandPath(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__MAX_FILE_SIZE_MB"); !v.empty()) cfg.logging.maxFileSizeMb = std::stoull(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__MAX_FILES"); !v.empty()) cfg.logging.maxFiles = std::stoull(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__DAILY_ROTATION"); !v.empty()) cfg.logging.dailyRotation = (toUpper(v) == "TRUE");

    if (auto v = getEnv("IDSENTINEL_SECURITY__HMAC_KEY"); !v.empty()) cfg.security.hmacKey = v;
}

std::optional<toml::table> parseConfigFile(const std::filesystem::path& path) {
    try {
        if (!std::filesystem::exists(path)) return std::nullopt;
        return toml::parse_file(path.string());
    } catch (const toml::parse_error& e) {
        SPDLOG_ERROR("Failed to parse config file {}: {}", path.string(), e.what());
        throw;
    }
}

std::filesystem::path findConfigFile(const std::optional<std::filesystem::path>& explicitPath) {
    if (explicitPath) return *explicitPath;

    if (auto v = getEnv("IDSENTINEL_CONFIG"); !v.empty()) {
        return expandPath(v);
    }

    std::filesystem::path cwd = std::filesystem::current_path() / "config.toml";
    if (std::filesystem::exists(cwd)) return cwd;

    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg) {
        std::filesystem::path p = std::filesystem::path(xdg) / "idsentinel" / "config.toml";
        if (std::filesystem::exists(p)) return p;
    }

    const char* home = std::getenv("HOME");
    if (!home) home = std::getenv("USERPROFILE");
    if (home) {
        std::filesystem::path p = std::filesystem::path(home) / ".config" / "idsentinel" / "config.toml";
        if (std::filesystem::exists(p)) return p;
    }

    #ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        std::filesystem::path p = std::filesystem::path(appdata) / "IDSentinel" / "config.toml";
        if (std::filesystem::exists(p)) return p;
    }
    const char* programdata = std::getenv("PROGRAMDATA");
    if (programdata) {
        std::filesystem::path p = std::filesystem::path(programdata) / "IDSentinel" / "config.toml";
        if (std::filesystem::exists(p)) return p;
    }
    #else
    std::filesystem::path p = "/etc/idsentinel/config.toml";
    if (std::filesystem::exists(p)) return p;
    #endif

    return {};
}

void parseConfig(const toml::table& tbl, Config& cfg) {
    if (auto net = tbl["network"]; net) {
        cfg.network.hrFeedUrl = getValueOr(*net, "hr_feed_url", cfg.network.hrFeedUrl);
        cfg.network.timeoutSeconds = getValueOr(*net, "timeout_seconds", cfg.network.timeoutSeconds);
        cfg.network.caBundlePath = getValueOr(*net, "ca_bundle_path", cfg.network.caBundlePath);
    }
    if (auto db = tbl["database"]; db) {
        if (auto p = (*db)["path"]; p) cfg.database.path = expandPath(p.value_or(""));
        cfg.database.walMode = getValueOr(*db, "wal_mode", cfg.database.walMode);
        cfg.database.busyTimeoutMs = getValueOr(*db, "busy_timeout_ms", cfg.database.busyTimeoutMs);
    }
    if (auto pol = tbl["policy"]; pol) {
        if (auto s = (*pol)["orphan_severity"]; s) cfg.policy.orphanSeverity = parseSeverity(s.value_or(""));
        if (auto s = (*pol)["missing_severity"]; s) cfg.policy.missingSeverity = parseSeverity(s.value_or(""));
    }
    if (auto log = tbl["logging"]; log) {
        if (auto l = (*log)["level"]; l) cfg.logging.level = parseLogLevel(l.value_or(""));
        if (auto f = (*log)["format"]; f) cfg.logging.format = parseLogFormat(f.value_or(""));
        if (auto f = (*log)["file"]; f) cfg.logging.file = expandPath(f.value_or(""));
        cfg.logging.maxFileSizeMb = getValueOr(*log, "max_size_mb", cfg.logging.maxFileSizeMb);
        cfg.logging.maxFiles = getValueOr(*log, "max_files", cfg.logging.maxFiles);
        cfg.logging.dailyRotation = getValueOr(*log, "daily", cfg.logging.dailyRotation);
    }
    if (auto sec = tbl["security"]; sec) {
        cfg.security.hmacKey = getValueOr(*sec, "hmac_key", cfg.security.hmacKey);
    }
}

void validateConfig(const Config& cfg) {
    if (cfg.network.hrFeedUrl.empty()) throw std::runtime_error("network.hr_feed_url is required");
    if (cfg.network.timeoutSeconds <= 0) throw std::runtime_error("network.timeout_seconds must be > 0");
    if (!cfg.database.path.empty() && cfg.database.path.has_parent_path()) {
        std::filesystem::create_directories(cfg.database.path.parent_path());
    }
    if (cfg.database.busyTimeoutMs < 0) throw std::runtime_error("database.busy_timeout_ms must be >= 0");
    if (!cfg.security.hmacKey.empty()) {
        // Basic base64 length check for 32-byte key (44 chars with padding)
        if (cfg.security.hmacKey.size() < 43) {
            SPDLOG_WARN("HMAC key appears too short for 32-byte key (got {} chars)", cfg.security.hmacKey.size());
        }
    }
}

void setDefaultPaths(Config& cfg) {
    if (cfg.database.path.empty()) cfg.database.path = getDefaultDatabasePath();
    if (cfg.logging.file.empty()) cfg.logging.file = getDefaultLogDirectory() / "idsentinel.log";
}
}

Config loadConfig(const std::optional<std::filesystem::path>& explicitPath) {
    Config cfg;
    auto configPath = findConfigFile(explicitPath);

    if (configPath.empty()) {
        SPDLOG_INFO("No config file found, using defaults with env overrides");
    } else {
        SPDLOG_INFO("Loading config from: {}", configPath.string());
        auto tbl = parseConfigFile(configPath);
        if (tbl) parseConfig(*tbl, cfg);
    }

    applyEnvOverrides(cfg);
    setDefaultPaths(cfg);
    validateConfig(cfg);

    SPDLOG_DEBUG("Config loaded: hrFeedUrl={}, dbPath={}, logLevel={}, hmacKeySet={}",
        cfg.network.hrFeedUrl, cfg.database.path.string(),
        static_cast<int>(cfg.logging.level), !cfg.security.hmacKey.empty());

    return cfg;
}

std::filesystem::path getDefaultConfigPath() {
    return findConfigFile(std::nullopt);
}

std::filesystem::path getDefaultDatabasePath() {
    #ifdef _WIN32
    const char* base = std::getenv("LOCALAPPDATA");
    if (!base) base = std::getenv("APPDATA");
    if (!base) base = ".";
    return std::filesystem::path(base) / "IDSentinel" / "compliance.db";
    #else
    const char* home = std::getenv("HOME");
    if (!home) home = ".";
    return std::filesystem::path(home) / ".local" / "share" / "idsentinel" / "compliance.db";
    #endif
}

std::filesystem::path getDefaultLogDirectory() {
    return getDefaultDatabasePath().parent_path() / "logs";
}