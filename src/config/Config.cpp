#include "Config.h"
#include <toml++/toml.h>
#include <spdlog/spdlog.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <charconv>
#include <array>
#include <algorithm>
#include <cstdint>
#include <openssl/evp.h>

namespace {
std::string toUpper(std::string s);
std::string getEnv(const char* name) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : "";
}

// EVP_DecodeBlock takes an int length; base64 keys are tiny, so report
// oversize input as invalid rather than implicitly narrowing size_t.
bool checkedKeyLength(std::size_t n, int& out) {
    if (n > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        return false;
    }
    out = static_cast<int>(n);
    return true;
}

template<typename T>
T getValueOr(const toml::table& tbl, const std::string& key, T defaultValue) {
    if (auto v = tbl[key]; v) return v.value_or(defaultValue);
    return defaultValue;
}

Result<void> checkFields(const toml::table& tbl, std::initializer_list<std::pair<std::string_view, char>> fields,
                         std::string_view section) {
    for (const auto& [key, node] : tbl) {
        auto it = std::find_if(fields.begin(), fields.end(), [&](const auto& field) { return field.first == key.str(); });
        const std::string fieldName = std::string(section) + "." + std::string(key.str());
        if (it == fields.end()) return Result<void>::err(Error{"CONFIG", "Unknown key: " + fieldName});
        const char kind = it->second;
        const bool typeOk = (kind == 's' && node.is_string()) || (kind == 'i' && node.is_integer()) ||
                            (kind == 'b' && node.is_boolean()) || (kind == 't' && node.is_table());
        if (!typeOk) return Result<void>::err(Error{"CONFIG", "Wrong type for " + fieldName});
        if (kind == 'i') {
            auto value = node.value<std::int64_t>();
            if (!value || *value < 0 || *value > (std::numeric_limits<int>::max)()) {
                return Result<void>::err(Error{"CONFIG", "Out-of-range value for " + fieldName});
            }
        }
    }
    return Result<void>::ok();
}

template <typename T>
Result<T> parseEnvInteger(const std::string& value, const char* name) {
    T parsed{};
    auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (ec != std::errc{} || end != value.data() + value.size()) {
        return Result<T>::err(Error{"CONFIG", std::string("Invalid ") + name + ": " + value});
    }
    return Result<T>::ok(parsed);
}

Result<bool> parseEnvBool(const std::string& value, const char* name) {
    const auto normalized = toUpper(value);
    if (normalized == "TRUE") return Result<bool>::ok(true);
    if (normalized == "FALSE") return Result<bool>::ok(false);
    return Result<bool>::err(Error{"CONFIG", std::string("Invalid ") + name + ": " + value});
}

std::filesystem::path expandPath(const std::string& pathStr) {
    if (pathStr.empty()) return {};
    std::string expanded = pathStr;
    if (expanded.starts_with("~")) {
        const char* home = std::getenv("HOME");
        if (!home) home = std::getenv("USERPROFILE");
        if (home) expanded.replace(0, 1, home);
    }
    // Do not probe or create the path during configuration. A dry run must
    // accept a database/log destination whose parent does not exist yet.
    return std::filesystem::path(expanded).lexically_normal();
}

std::string toUpper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}
}

Result<LogLevel> parseLogLevel(const std::string& s) {
    auto u = toUpper(s);
    if (u == "TRACE") return Result<LogLevel>::ok(LogLevel::Trace);
    if (u == "DEBUG") return Result<LogLevel>::ok(LogLevel::Debug);
    if (u == "INFO") return Result<LogLevel>::ok(LogLevel::Info);
    if (u == "WARN" || u == "WARNING") return Result<LogLevel>::ok(LogLevel::Warn);
    if (u == "ERROR") return Result<LogLevel>::ok(LogLevel::Error);
    if (u == "CRITICAL") return Result<LogLevel>::ok(LogLevel::Critical);
    return Result<LogLevel>::err(Error{ "CONFIG", "Invalid log level: " + s });
}

Result<LogFormat> parseLogFormat(const std::string& s) {
    auto u = toUpper(s);
    if (u == "JSON") return Result<LogFormat>::ok(LogFormat::Json);
    if (u == "TEXT") return Result<LogFormat>::ok(LogFormat::Text);
    return Result<LogFormat>::err(Error{ "CONFIG", "Invalid log format: " + s });
}

Result<Severity> parseSeverity(const std::string& s) {
    auto u = toUpper(s);
    if (u == "CRITICAL") return Result<Severity>::ok(Severity::Critical);
    if (u == "HIGH") return Result<Severity>::ok(Severity::High);
    if (u == "MEDIUM") return Result<Severity>::ok(Severity::Medium);
    if (u == "LOW") return Result<Severity>::ok(Severity::Low);
    return Result<Severity>::err(Error{ "CONFIG", "Invalid severity: " + s });
}

Result<void> applyEnvOverrides(Config& cfg) { // NOLINT(readability-function-cognitive-complexity): independent environment field parsing with early error returns
    if (auto v = getEnv("IDSENTINEL_NETWORK__HR_FEED_URL"); !v.empty()) cfg.network.hrFeedUrl = v;
    if (auto v = getEnv("IDSENTINEL_NETWORK__TIMEOUT_SECONDS"); !v.empty()) {
        auto r = parseEnvInteger<int>(v, "timeout_seconds");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.network.timeoutSeconds = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_NETWORK__CA_BUNDLE_PATH"); !v.empty()) cfg.network.caBundlePath = v;
    if (auto v = getEnv("IDSENTINEL_NETWORK__MAX_RESPONSE_MB"); !v.empty()) {
        auto r = parseEnvInteger<int>(v, "max_response_mb");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.network.maxResponseMb = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_NETWORK__MAX_RETRIES"); !v.empty()) {
        auto r = parseEnvInteger<int>(v, "max_retries");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.network.maxRetries = r.value();
    }

    if (auto v = getEnv("IDSENTINEL_DATABASE__PATH"); !v.empty()) cfg.database.path = expandPath(v);
    if (auto v = getEnv("IDSENTINEL_DATABASE__WAL_MODE"); !v.empty()) {
        auto r = parseEnvBool(v, "wal_mode");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.database.walMode = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_DATABASE__BUSY_TIMEOUT_MS"); !v.empty()) {
        auto r = parseEnvInteger<int>(v, "busy_timeout_ms");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.database.busyTimeoutMs = r.value();
    }

    if (auto v = getEnv("IDSENTINEL_POLICY__ORPHAN_SEVERITY"); !v.empty()) {
        auto r = parseSeverity(v);
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.policy.orphanSeverity = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_POLICY__MISSING_SEVERITY"); !v.empty()) {
        auto r = parseSeverity(v);
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.policy.missingSeverity = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_POLICY__DRIFT_SEVERITY"); !v.empty()) {
        auto r = parseSeverity(v);
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.policy.driftSeverity = r.value();
    }

    if (auto v = getEnv("IDSENTINEL_SOURCE__MAX_FILE_AGE_HOURS"); !v.empty()) {
        auto r = parseEnvInteger<int>(v, "max_file_age_hours");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.source.maxFileAgeHours = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_SOURCE__HR_FALLBACK_PATH"); !v.empty()) cfg.source.hrFallbackPath = expandPath(v);
    if (auto v = getEnv("IDSENTINEL_SOURCE__TARGET_PATH"); !v.empty()) cfg.source.targetPath = expandPath(v);

    if (auto v = getEnv("IDSENTINEL_LOGGING__LEVEL"); !v.empty()) {
        auto r = parseLogLevel(v);
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.logging.level = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_LOGGING__FORMAT"); !v.empty()) {
        auto r = parseLogFormat(v);
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.logging.format = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_LOGGING__FILE"); !v.empty()) cfg.logging.file = expandPath(v);
    if (auto v = getEnv("IDSENTINEL_LOGGING__MAX_FILE_SIZE_MB"); !v.empty()) {
        auto r = parseEnvInteger<size_t>(v, "max_file_size_mb");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.logging.maxFileSizeMb = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_LOGGING__MAX_FILES"); !v.empty()) {
        auto r = parseEnvInteger<size_t>(v, "max_files");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.logging.maxFiles = r.value();
    }
    if (auto v = getEnv("IDSENTINEL_LOGGING__DAILY_ROTATION"); !v.empty()) {
        auto r = parseEnvBool(v, "daily_rotation");
        if (r.hasError()) return Result<void>::err(r.error());
        cfg.logging.dailyRotation = r.value();
    }

    if (auto v = getEnv("IDSENTINEL_SECURITY__HMAC_KEY"); !v.empty()) cfg.security.hmacKey = v;
    return Result<void>::ok();
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

Result<void> parseConfig(const toml::table& tbl, Config& cfg) { // NOLINT(readability-function-cognitive-complexity): one branch per config section; each branch is a straight mapping
    if (auto r = checkFields(tbl, {{"network", 't'}, {"database", 't'}, {"policy", 't'},
                                   {"source", 't'}, {"logging", 't'}, {"security", 't'}}, "root"); r.hasError()) return r;
    if (auto net = tbl["network"]; net && net.is_table()) {
        auto& netTbl = *net.as_table();
        if (auto r = checkFields(netTbl, {{"hr_feed_url", 's'}, {"timeout_seconds", 'i'},
              {"ca_bundle_path", 's'}, {"max_response_mb", 'i'}, {"max_retries", 'i'}}, "network"); r.hasError()) return r;
        cfg.network.hrFeedUrl = getValueOr(netTbl, "hr_feed_url", cfg.network.hrFeedUrl);
        cfg.network.timeoutSeconds = getValueOr(netTbl, "timeout_seconds", cfg.network.timeoutSeconds);
        cfg.network.caBundlePath = getValueOr(netTbl, "ca_bundle_path", cfg.network.caBundlePath);
        cfg.network.maxResponseMb = getValueOr(netTbl, "max_response_mb", cfg.network.maxResponseMb);
        cfg.network.maxRetries = getValueOr(netTbl, "max_retries", cfg.network.maxRetries);
    }
    if (auto db = tbl["database"]; db && db.is_table()) {
        auto& dbTbl = *db.as_table();
        if (auto r = checkFields(dbTbl, {{"path", 's'}, {"wal_mode", 'b'},
              {"busy_timeout_ms", 'i'}}, "database"); r.hasError()) return r;
        if (auto p = dbTbl["path"]; p) cfg.database.path = expandPath(p.value_or(""));
        cfg.database.walMode = getValueOr(dbTbl, "wal_mode", cfg.database.walMode);
        cfg.database.busyTimeoutMs = getValueOr(dbTbl, "busy_timeout_ms", cfg.database.busyTimeoutMs);
    }
    if (auto pol = tbl["policy"]; pol && pol.is_table()) {
        auto& polTbl = *pol.as_table();
        if (auto r = checkFields(polTbl, {{"orphan_severity", 's'}, {"missing_severity", 's'},
              {"drift_severity", 's'}}, "policy"); r.hasError()) return r;
        if (auto s = polTbl["orphan_severity"]; s) {
            auto r = parseSeverity(s.value_or(""));
            if (r.hasError()) return Result<void>::err(Error{ "CONFIG", r.error().message });
            cfg.policy.orphanSeverity = r.value();
        }
        if (auto s = polTbl["missing_severity"]; s) {
            auto r = parseSeverity(s.value_or(""));
            if (r.hasError()) return Result<void>::err(Error{ "CONFIG", r.error().message });
            cfg.policy.missingSeverity = r.value();
        }
        if (auto s = polTbl["drift_severity"]; s) {
            auto r = parseSeverity(s.value_or(""));
            if (r.hasError()) return Result<void>::err(Error{ "CONFIG", r.error().message });
            cfg.policy.driftSeverity = r.value();
        }
    }
    if (auto src = tbl["source"]; src && src.is_table()) {
        auto& srcTbl = *src.as_table();
        if (auto r = checkFields(srcTbl, {{"max_file_age_hours", 'i'},
              {"hr_fallback_path", 's'}, {"target_path", 's'}}, "source"); r.hasError()) return r;
        cfg.source.maxFileAgeHours = getValueOr(srcTbl, "max_file_age_hours", cfg.source.maxFileAgeHours);
        if (auto p = srcTbl["hr_fallback_path"]; p) cfg.source.hrFallbackPath = p.value_or("");
        if (auto p = srcTbl["target_path"]; p) cfg.source.targetPath = p.value_or("");
    }
    if (auto log = tbl["logging"]; log && log.is_table()) {
        auto& logTbl = *log.as_table();
        if (auto r = checkFields(logTbl, {{"level", 's'}, {"format", 's'}, {"file", 's'},
              {"rotation", 't'}, {"max_size_mb", 'i'}, {"max_files", 'i'}, {"daily", 'b'}}, "logging"); r.hasError()) return r;
        if (auto l = logTbl["level"]; l) {
            auto r = parseLogLevel(l.value_or(""));
            if (r.hasError()) return Result<void>::err(Error{ "CONFIG", r.error().message });
            cfg.logging.level = r.value();
        }
        if (auto f = logTbl["format"]; f) {
            auto r = parseLogFormat(f.value_or(""));
            if (r.hasError()) return Result<void>::err(Error{ "CONFIG", r.error().message });
            cfg.logging.format = r.value();
        }
        if (auto f = logTbl["file"]; f) cfg.logging.file = expandPath(f.value_or(""));

        // Parse nested rotation table
        if (auto rot = logTbl["rotation"]; rot && rot.is_table()) {
            auto& rotTbl = *rot.as_table();
            if (auto r = checkFields(rotTbl, {{"max_size_mb", 'i'}, {"max_files", 'i'},
                  {"daily", 'b'}}, "logging.rotation"); r.hasError()) return r;
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
        if (auto r = checkFields(secTbl, {{"hmac_key", 's'}}, "security"); r.hasError()) return r;
        cfg.security.hmacKey = getValueOr(secTbl, "hmac_key", cfg.security.hmacKey);
    }
    return Result<void>::ok();
}

Result<void> validateConfig(const Config& cfg) { // NOLINT(readability-function-cognitive-complexity): independent bounds and key validation
    constexpr int kHmacKeyBytes = 32;
    constexpr int kMaxTimeoutSeconds = 3600;
    constexpr int kMaxResponseMb = 1024;
    constexpr size_t kMaxLogSizeMb = 1024;
    constexpr size_t kMaxLogFiles = 1000;
    if (cfg.network.hrFeedUrl.empty()) return Result<void>::err(Error{ "CONFIG", "network.hr_feed_url is required" });
    if (cfg.network.timeoutSeconds <= 0) return Result<void>::err(Error{ "CONFIG", "network.timeout_seconds must be > 0" });
    if (cfg.network.timeoutSeconds > kMaxTimeoutSeconds) return Result<void>::err(Error{ "CONFIG", "network.timeout_seconds must be <= 3600" });
    if (cfg.network.maxResponseMb <= 0) return Result<void>::err(Error{ "CONFIG", "network.max_response_mb must be > 0" });
    if (cfg.network.maxResponseMb > kMaxResponseMb) return Result<void>::err(Error{ "CONFIG", "network.max_response_mb must be <= 1024" });
    if (cfg.network.maxRetries < 0) return Result<void>::err(Error{ "CONFIG", "network.max_retries must be >= 0" });
    if (cfg.network.maxRetries > 10) return Result<void>::err(Error{ "CONFIG", "network.max_retries must be <= 10" });
    if (cfg.database.busyTimeoutMs < 0) return Result<void>::err(Error{ "CONFIG", "database.busy_timeout_ms must be >= 0" });
    if (cfg.source.maxFileAgeHours < 0) return Result<void>::err(Error{ "CONFIG", "source.max_file_age_hours must be >= 0" });
    if (cfg.logging.maxFileSizeMb == 0 || cfg.logging.maxFileSizeMb > kMaxLogSizeMb ||
        cfg.logging.maxFiles == 0 || cfg.logging.maxFiles > kMaxLogFiles) {
        return Result<void>::err(Error{"CONFIG", "logging rotation limits out of range"});
    }
    if (!cfg.security.hmacKey.empty()) {
        // Validate base64 encoding and length for 32-byte key
        // (EVP_DecodeBlock does not discount '=' padding: a 32-byte key is
        // 44 base64 chars ending in '=', decoding to raw length 33)
        std::string decoded;
        decoded.resize(cfg.security.hmacKey.size());
        int keyLen = 0;
        if (!checkedKeyLength(cfg.security.hmacKey.size(), keyLen)) {
            return Result<void>::err(Error{ "CONFIG", "security.hmac_key must be a valid base64-encoded 32-byte key (encoding too large)" });
        }
        int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL C API requires unsigned char*
                                  reinterpret_cast<const unsigned char*>(cfg.security.hmacKey.data()), keyLen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL C API requires unsigned char*
        const std::string& key = cfg.security.hmacKey;
        if (!key.empty() && key.back() == '=') --len;
        if (key.size() >= 2 && key[key.size() - 2] == '=') --len;
        if (len != kHmacKeyBytes) {
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

    if (explicitPath && configPath.empty()) {
        return Result<Config>::err(Error{ "CONFIG", "Config file not found: " + explicitPath->string() });
    }
    if (!configPath.empty() && !std::filesystem::exists(configPath)) {
        return Result<Config>::err(Error{"CONFIG", "Config file not found: " + configPath.string()});
    }

    if (configPath.empty()) {
        SPDLOG_INFO("No config file found, using defaults with env overrides");
    } else {
        SPDLOG_INFO("Loading config from: {}", configPath.string());
        auto tblResult = parseConfigFile(configPath);
        if (tblResult.hasError()) {
            return Result<Config>::err(tblResult.error());
        }
        const auto& parsedTable = tblResult.value();
        if (parsedTable.has_value()) {
            if (auto r = parseConfig(*parsedTable, cfg); r.hasError()) {
                return Result<Config>::err(r.error());
            }
            auto resolveSource = [&](std::filesystem::path& path) {
                if (!path.empty() && path.is_relative()) path = configPath.parent_path() / path;
            };
            resolveSource(cfg.source.hrFallbackPath);
            resolveSource(cfg.source.targetPath);
        }
    }

    if (auto r = applyEnvOverrides(cfg); r.hasError()) {
        return Result<Config>::err(r.error());
    }
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
