#include "Config.h"
#include <toml++/toml.h>
#include <spdlog/spdlog.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <openssl/evp.h>

namespace {
std::string getEnv(const char* name) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : "";
}

template<typename T>
T getValueOr(const toml::table& tbl, const std::string& key, T defaultValue) {
    if (auto v = tbl[key]; v) return v.value_or(defaultValue);
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
    if (auto v = getEnv("IDSENTINEL_NETWORK__MAX_RESPONSE_MB"); !v.empty()) cfg.network.maxResponseMb = std::stoi(v);
    if (auto v = getEnv("IDSENTINEL_NETWORK__MAX_RETRIES"); !v.empty()) cfg.network.maxRetries = std::stoi(v);

    if (auto v = getEnv("IDSENTINEL_DATABASE__PATH"); !v.empty()) cfg.database.path = expandPath(v);
    if (auto v = getEnv("IDSENTINEL_DATABASE__WAL_MODE"); !v.empty()) cfg.database.walMode = (toUpper(v) == "TRUE");
    if (auto v = getEnv("IDSENTINEL_DATABASE__BUSY_TIMEOUT_MS"); !v.empty()) cfg.database.busyTimeoutMs = std::stoi(v);

    if (auto v = getEnv("IDSENTINEL_POLICY__ORPHAN_SEVERITY"); !v.empty()) cfg.policy.orphanSeverity = parseSeverity(v);
    if (auto v = getEnv("IDSENTINEL_POLICY__MISSING_SEVERITY"); !v.empty()) cfg.policy.missingSeverity = parseSeverity(v);
    if (auto v = getEnv("IDSENTINEL_POLICY__DRIFT_SEVERITY"); !v.empty()) cfg.policy.driftSeverity = parseSeverity(v);

    if (auto v = getEnv("IDSENTINEL_SOURCE__MAX_FILE_AGE_HOURS"); !v.empty()) cfg.source.maxFileAgeHours = std::stoi(v);

    if (auto v = getEnv("IDSENTINEL_LOGGING__LEVEL"); !v.empty()) cfg.logging.level = parseLogLevel(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__FORMAT"); !v.empty()) cfg.logging.format = parseLogFormat(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__FILE"); !v.empty()) cfg.logging.file = expandPath(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__MAX_FILE_SIZE_MB"); !v.empty()) cfg.logging.maxFileSizeMb = std::stoull(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__MAX_FILES"); !v.empty()) cfg.logging.maxFiles = std::stoull(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__DAILY_ROTATION"); !v.empty()) cfg.logging.dailyRotation = (toUpper(v) == "TRUE");

    if (auto v = getEnv("IDSENTINEL_SECURITY__HMAC_KEY"); !v.empty()) cfg.security.hmacKey = v;
}

Result<std::optional<toml::table>> parseConfigFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return Result<std::optional<toml::table>>::ok(std::nullopt);
    try {
        return Result<std::optional<toml::table>>::ok(toml::parse_file(path.string()));
    } catch (const toml::parse_error& e) {
        SPDLOG_ERROR("Failed to parse config file {}: {}", path.string(), e.what());
        return Result<std::optional<toml::table>>::err(Error{ "CONFIG_PARSE", e.what() });
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
    if (auto net = tbl["network"]; net && net.is_table()) {
        auto& netTbl = *net.as_table();
        cfg.network.hrFeedUrl = getValueOr(netTbl, "hr_feed_url", cfg.network.hrFeedUrl);
        cfg.network.timeoutSeconds = getValueOr(netTbl, "timeout_seconds", cfg.network.timeoutSeconds);
        cfg.network.caBundlePath = getValueOr(netTbl, "ca_bundle_path", cfg.network.caBundlePath);
        cfg.network.maxResponseMb = getValueOr(netTbl, "max_response_mb", cfg.network.maxResponseMb);
        cfg.network.maxRetries = getValueOr(netTbl, "max_retries", cfg.network.maxRetries);
    }
    if (auto db = tbl["database"]; db && db.is_table()) {
        auto& dbTbl = *db.as_table();
        if (auto p = dbTbl["path"]; p) cfg.database.path = expandPath(p.value_or(""));
        cfg.database.walMode = getValueOr(dbTbl, "wal_mode", cfg.database.walMode);
        cfg.database.busyTimeoutMs = getValueOr(dbTbl, "busy_timeout_ms", cfg.database.busyTimeoutMs);
    }
    if (auto pol = tbl["policy"]; pol && pol.is_table()) {
        auto& polTbl = *pol.as_table();
        if (auto s = polTbl["orphan_severity"]; s) cfg.policy.orphanSeverity = parseSeverity(s.value_or(""));
        if (auto s = polTbl["missing_severity"]; s) cfg.policy.missingSeverity = parseSeverity(s.value_or(""));
        if (auto s = polTbl["drift_severity"]; s) cfg.policy.driftSeverity = parseSeverity(s.value_or(""));
    }
    if (auto src = tbl["source"]; src && src.is_table()) {
        auto& srcTbl = *src.as_table();
        cfg.source.maxFileAgeHours = getValueOr(srcTbl, "max_file_age_hours", cfg.source.maxFileAgeHours);
    }
    if (auto log = tbl["logging"]; log && log.is_table()) {
        auto& logTbl = *log.as_table();
        if (auto l = logTbl["level"]; l) cfg.logging.level = parseLogLevel(l.value_or(""));
        if (auto f = logTbl["format"]; f) cfg.logging.format = parseLogFormat(f.value_or(""));
        if (auto f = logTbl["file"]; f) cfg.logging.file = expandPath(f.value_or(""));
        
        // Parse nested rotation table
        if (auto rot = logTbl["rotation"]; rot && rot.is_table()) {
            auto& rotTbl = *rot.as_table();
            LoggingConfig::RotationConfig rotation;
            rotation.maxSizeMb = getValueOr(rotTbl, "max_size_mb", rotation.maxSizeMb);
            rotation.maxFiles = getValueOr(rotTbl, "max_files", rotation.maxFiles);
            rotation.daily = getValueOr(rotTbl, "daily", rotation.daily);
            cfg.logging.rotation = rotation;
            
            // Use rotation values for backward compatibility
            cfg.logging.maxFileSizeMb = rotation.maxSizeMb;
            cfg.logging.maxFiles = rotation.maxFiles;
            cfg.logging.dailyRotation = rotation.daily;
        } else {
            // Fallback to flat keys for backward compatibility
            cfg.logging.maxFileSizeMb = getValueOr(logTbl, "max_size_mb", cfg.logging.maxFileSizeMb);
            cfg.logging.maxFiles = getValueOr(logTbl, "max_files", cfg.logging.maxFiles);
            cfg.logging.dailyRotation = getValueOr(logTbl, "daily", cfg.logging.dailyRotation);
        }
    }
    if (auto sec = tbl["security"]; sec && sec.is_table()) {
        auto& secTbl = *sec.as_table();
        cfg.security.hmacKey = getValueOr(secTbl, "hmac_key", cfg.security.hmacKey);
    }
}

Result<void> validateConfig(const Config& cfg) {
    if (cfg.network.hrFeedUrl.empty()) return Result<void>::err(Error{ "CONFIG", "network.hr_feed_url is required" });
    if (cfg.network.timeoutSeconds <= 0) return Result<void>::err(Error{ "CONFIG", "network.timeout_seconds must be > 0" });
    if (cfg.network.maxResponseMb <= 0) return Result<void>::err(Error{ "CONFIG", "network.max_response_mb must be > 0" });
    if (cfg.network.maxRetries < 0) return Result<void>::err(Error{ "CONFIG", "network.max_retries must be >= 0" });
    if (!cfg.database.path.empty() && cfg.database.path.has_parent_path()) {
        std::filesystem::create_directories(cfg.database.path.parent_path());
    }
    if (cfg.database.busyTimeoutMs < 0) return Result<void>::err(Error{ "CONFIG", "database.busy_timeout_ms must be >= 0" });
    if (cfg.source.maxFileAgeHours < 0) return Result<void>::err(Error{ "CONFIG", "source.max_file_age_hours must be >= 0" });
    if (!cfg.security.hmacKey.empty()) {
        // Validate base64 encoding and length for 32-byte key
        // (EVP_DecodeBlock does not discount '=' padding: a 32-byte key is
        // 44 base64 chars ending in '=', decoding to raw length 33)
        std::string decoded;
        decoded.resize(cfg.security.hmacKey.size());
        int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()),
                                  reinterpret_cast<const unsigned char*>(cfg.security.hmacKey.data()), cfg.security.hmacKey.size());
        const std::string& key = cfg.security.hmacKey;
        if (key.size() >= 1 && key.back() == '=') --len;
        if (key.size() >= 2 && key[key.size() - 2] == '=') --len;
        if (len != 32) {
            return Result<void>::err(Error{ "CONFIG", "security.hmac_key must be a valid base64-encoded 32-byte key (got " + std::to_string(len) + " bytes)" });
        }
    }
    return Result<void>::ok();
}

void setDefaultPaths(Config& cfg) {
    if (cfg.database.path.empty()) cfg.database.path = getDefaultDatabasePath();
    // File logging is opt-in: an empty logging.file means console only.
    // Operators enable it explicitly via config file or IDSENTINEL_LOGGING__FILE.
}

Result<Config> loadConfig(const std::optional<std::filesystem::path>& explicitPath) {
    Config cfg;
    auto configPath = findConfigFile(explicitPath);

    if (configPath.empty()) {
        SPDLOG_INFO("No config file found, using defaults with env overrides");
    } else {
        SPDLOG_INFO("Loading config from: {}", configPath.string());
        auto tblResult = parseConfigFile(configPath);
        if (tblResult.hasError()) {
            return Result<Config>::err(tblResult.error());
        }
        if (tblResult.value()) parseConfig(*tblResult.value(), cfg);
    }

    applyEnvOverrides(cfg);
    setDefaultPaths(cfg);
    if (auto r = validateConfig(cfg); r.hasError()) {
        return Result<Config>::err(r.error());
    }

    SPDLOG_DEBUG("Config loaded: dbPath={}, logLevel={}, hmacKeySet={}",
        cfg.database.path.string(),
        static_cast<int>(cfg.logging.level), !cfg.security.hmacKey.empty());

    return Result<Config>::ok(std::move(cfg));
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