#include "CLI.h"
#include "Config.h"
#include "core/Reconciler.h"
#include "core/Logging.h"
#include "parsers/CSVParser.h"
#include "persistence/ComplianceStore.h"
#include "connectors/NetworkConnector.h"
#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include <fmt/core.h>
#include <sqlite3.h>

namespace {
std::string base64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.resize(4 * ((len + 2) / 3));
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    int outl = 0;
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, reinterpret_cast<unsigned char*>(out.data()), &outl, data, static_cast<int>(len));
    int final_len = 0;
    EVP_EncodeFinal(ctx, reinterpret_cast<unsigned char*>(out.data() + outl), &final_len);
    EVP_ENCODE_CTX_free(ctx);
    out.resize(outl + final_len);
    return out;
}

std::string hexEncode(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

void printConfig(const Config& cfg) {
    fmt::print("Network:\n");
    fmt::print("  hr_feed_url: {}\n", cfg.network.hrFeedUrl);
    fmt::print("  timeout_seconds: {}\n", cfg.network.timeoutSeconds);
    fmt::print("  ca_bundle_path: {}\n", cfg.network.caBundlePath.empty() ? "(system default)" : cfg.network.caBundlePath);
    fmt::print("\nDatabase:\n");
    fmt::print("  path: {}\n", cfg.database.path.string());
    fmt::print("  wal_mode: {}\n", cfg.database.walMode ? "true" : "false");
    fmt::print("  busy_timeout_ms: {}\n", cfg.database.busyTimeoutMs);
    fmt::print("\nPolicy:\n");
    fmt::print("  orphan_severity: {}\n", toString(cfg.policy.orphanSeverity));
    fmt::print("  missing_severity: {}\n", toString(cfg.policy.missingSeverity));
    fmt::print("\nLogging:\n");
    fmt::print("  level: {}\n", static_cast<int>(cfg.logging.level));
    fmt::print("  format: {}\n", cfg.logging.format == LogFormat::Json ? "json" : "text");
    fmt::print("  file: {}\n", cfg.logging.file.string());
    fmt::print("  max_file_size_mb: {}\n", cfg.logging.maxFileSizeMb);
    fmt::print("  max_files: {}\n", cfg.logging.maxFiles);
    fmt::print("  daily_rotation: {}\n", cfg.logging.dailyRotation ? "true" : "false");
    fmt::print("\nSecurity:\n");
    fmt::print("  hmac_key: {}\n", cfg.security.hmacKey.empty() ? "(not set)" : "(set)");
}
}

Result<CLIOptions> parseCLI(int argc, char* argv[]) {
    CLIOptions opts;
    CLI::App app("IDSentinel - Identity Reconciliation Engine");

    auto* reconcile = app.add_subcommand("reconcile", "Run identity reconciliation (default)");
    reconcile->add_flag("--dry-run", opts.dryRun, "Preview violations without writing to database");
    reconcile->add_option("--config", opts.configPath, "Path to config file");

    auto* inspect = app.add_subcommand("inspect", "Inspect reconciliation run results");
    inspect->add_option("--run-id", opts.runId, "Run ID to inspect")->required();
    inspect->add_option("--format", opts.inspectFormat, "Output format: table, json")->check(CLI::IsMember({"table", "json"}));
    inspect->add_option("--config", opts.configPath, "Path to config file");

    auto* configCmd = app.add_subcommand("config", "Show or validate configuration");
    configCmd->add_flag("--validate", opts.validateOnly, "Validate config and exit");
    configCmd->add_option("--config", opts.configPath, "Path to config file");

    auto* keygen = app.add_subcommand("keygen", "Generate HMAC key");
    keygen->add_option("--bits", opts.keyBits, "Key size in bits")->check(CLI::IsMember({256}));
    keygen->add_option("--format", opts.keyFormat, "Output format")->check(CLI::IsMember({"base64", "hex"}));

    app.set_config("--config", "", "Config file", false);
    app.require_subcommand(0, 1);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    if (app.get_subcommands().empty()) {
        opts.command = CLIOptions::Command::Reconcile;
    } else {
        const std::string& cmd = app.get_subcommands()[0]->get_name();
        if (cmd == "reconcile") opts.command = CLIOptions::Command::Reconcile;
        else if (cmd == "inspect") opts.command = CLIOptions::Command::Inspect;
        else if (cmd == "config") opts.command = CLIOptions::Command::Config;
        else if (cmd == "keygen") opts.command = CLIOptions::Command::Keygen;
    }

    return Result<CLIOptions>::ok(opts);
}

int runReconcile(const CLIOptions& opts) {
    auto cfgResult = loadConfig(opts.configPath);
    if (cfgResult.hasError()) {
        SPDLOG_ERROR("Failed to load config: {}", cfgResult.error().message);
        return 1;
    }
    Config cfg = std::move(cfgResult.value());

    initLogging(cfg.logging.format, cfg.logging.level, cfg.logging.file,
                cfg.logging.maxFileSizeMb, cfg.logging.maxFiles, cfg.logging.dailyRotation);

    SPDLOG_INFO("Starting IDSentinel reconciliation");

    // Fetch HR feed
    NetworkConnector net;
    net.setTimeouts(cfg.network.timeoutSeconds, cfg.network.timeoutSeconds);
    if (!cfg.network.caBundlePath.empty()) {
        net.setCABundle(cfg.network.caBundlePath);
    }

    SPDLOG_INFO("Fetching HR feed from: {}", cfg.network.hrFeedUrl);
    auto hrResult = net.fetch(cfg.network.hrFeedUrl);
    std::string hrCsv;
    if (hrResult.hasError()) {
        SPDLOG_WARN("Network fetch failed: {}. Falling back to local cache.", hrResult.error().message);
    } else {
        hrCsv = std::move(hrResult.value());
    }

    // Parse HR
    std::unordered_map<std::string, Identity> hrIdentities;
    if (!hrCsv.empty()) {
        auto parseResult = CSVParser::parse(hrCsv);
        if (parseResult.hasError()) {
            SPDLOG_ERROR("Failed to parse HR feed: {}", parseResult.error().message);
            return 1;
        }
        hrIdentities = std::move(parseResult.value());
    }

    if (hrIdentities.empty()) {
        // Fallback to local file
        std::filesystem::path localPath = "data/hr_feed.csv";
        if (std::filesystem::exists(localPath)) {
            SPDLOG_INFO("Loading HR feed from local file: {}", localPath.string());
            auto fileResult = CSVParser::loadFromFile(localPath);
            if (fileResult.hasError()) {
                SPDLOG_ERROR("Failed to load local HR feed: {}", fileResult.error().message);
                return 1;
            }
            auto parseResult = CSVParser::parse(fileResult.value());
            if (parseResult.hasError()) {
                SPDLOG_ERROR("Failed to parse local HR feed: {}", parseResult.error().message);
                return 1;
            }
            hrIdentities = std::move(parseResult.value());
        }
    }

    if (hrIdentities.empty()) {
        SPDLOG_CRITICAL("No valid HR data available. Aborting reconciliation.");
        return 1;
    }
    SPDLOG_INFO("Loaded {} HR identities", hrIdentities.size());

    // Load system dump
    std::filesystem::path systemPath = "data/system_dump.csv";
    if (!std::filesystem::exists(systemPath)) {
        SPDLOG_CRITICAL("System dump not found: {}", systemPath.string());
        return 1;
    }

    auto sysFileResult = CSVParser::loadFromFile(systemPath);
    if (sysFileResult.hasError()) {
        SPDLOG_ERROR("Failed to load system dump: {}", sysFileResult.error().message);
        return 1;
    }

    auto sysParseResult = CSVParser::parse(sysFileResult.value());
    if (sysParseResult.hasError()) {
        SPDLOG_ERROR("Failed to parse system dump: {}", sysParseResult.error().message);
        return 1;
    }
    auto systemIdentities = std::move(sysParseResult.value());
    SPDLOG_INFO("Loaded {} system identities", systemIdentities.size());

    // Initialize database
    ComplianceStore store(cfg.database.path, cfg.database.walMode, cfg.database.busyTimeoutMs);
    if (auto r = store.init(); r.hasError()) {
        SPDLOG_ERROR("Failed to initialize database: {}", r.error().message);
        return 1;
    }

    // Run reconciliation
    Reconciler reconciler(store, cfg.security.hmacKey);
    auto mode = opts.dryRun ? Reconciler::RunMode::DryRun : Reconciler::RunMode::Normal;
    auto result = reconciler.runReconciliation(hrIdentities, systemIdentities, mode);

    if (result.hasError()) {
        SPDLOG_ERROR("Reconciliation failed: {}", result.error().message);
        return 1;
    }

    const auto& res = result.value();
    fmt::print("\nReconciliation Summary:\n");
    fmt::print("  Run ID: {}\n", res.runId);
    fmt::print("  Orphan Accounts: {}\n", res.orphanCount);
    fmt::print("  Missing Accounts: {}\n", res.missingCount);
    fmt::print("  Status: {}\n", res.success ? "SUCCESS" : "FAILED");

    if (opts.dryRun) {
        fmt::print("\n[DRY-RUN] No changes written to database.\n");
    }

    return res.success ? 0 : 1;
}

int runInspect(const CLIOptions& opts) {
    auto cfgResult = loadConfig(opts.configPath);
    if (cfgResult.hasError()) {
        SPDLOG_ERROR("Failed to load config: {}", cfgResult.error().message);
        return 1;
    }
    Config cfg = std::move(cfgResult.value());

    initLogging(cfg.logging.format, cfg.logging.level, cfg.logging.file,
                cfg.logging.maxFileSizeMb, cfg.logging.maxFiles, cfg.logging.dailyRotation);

    ComplianceStore store(cfg.database.path);
    if (auto r = store.init(); r.hasError()) {
        SPDLOG_ERROR("Failed to initialize database: {}", r.error().message);
        return 1;
    }

    sqlite3* db = nullptr;
    if (sqlite3_open(cfg.database.path.string().c_str(), &db) != SQLITE_OK) {
        SPDLOG_ERROR("Failed to open database");
        return 1;
    }

    std::string sql = R"(
        SELECT finding_id, run_id, user_id, violation_type, severity, detected_at, status, integrity_hash
        FROM compliance_findings
        WHERE run_id = ?
        ORDER BY finding_id
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        SPDLOG_ERROR("Failed to prepare query: {}", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(stmt, 1, opts.runId.c_str(), -1, SQLITE_TRANSIENT);

    if (opts.inspectFormat == "json") {
        nlohmann::json findings = nlohmann::json::array();
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            nlohmann::json f;
            f["finding_id"] = sqlite3_column_int(stmt, 0);
            f["run_id"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            f["user_id"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            f["violation_type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            f["severity"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            f["detected_at"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            f["status"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            f["integrity_hash"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            findings.push_back(f);
        }
        fmt::print("{}\n", findings.dump(2));
    } else {
        fmt::print("{:<12} {:<20} {:<15} {:<18} {:<10} {:<20} {:<12} {}\n",
            "Finding ID", "Run ID", "User ID", "Violation Type", "Severity", "Detected At", "Status", "Integrity Hash");
        fmt::print("{:-<12} {:-<20} {:-<15} {:-<18} {:-<10} {:-<20} {:-<12} {:-<64}\n", "", "", "", "", "", "", "", "");

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            fmt::print("{:<12} {:<20} {:<15} {:<18} {:<10} {:<20} {:<12} {}\n",
                sqlite3_column_int(stmt, 0),
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)),
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)),
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)),
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)),
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)),
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)),
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7))
            );
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int runConfig(const CLIOptions& opts) {
    auto cfgResult = loadConfig(opts.configPath);
    if (cfgResult.hasError()) {
        fmt::print("Config validation failed: {}\n", cfgResult.error().message);
        return 1;
    }
    Config cfg = std::move(cfgResult.value());

    if (opts.validateOnly) {
        fmt::print("Config validation passed.\n");
        return 0;
    }

    printConfig(cfg);
    return 0;
}

int runKeygen(const CLIOptions& opts) {
    std::vector<uint8_t> key(opts.keyBits / 8);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        fmt::print("Failed to generate random key\n");
        return 1;
    }

    if (opts.keyFormat == "base64") {
        fmt::print("{}\n", base64Encode(key.data(), key.size()));
    } else {
        fmt::print("{}\n", hexEncode(key.data(), key.size()));
    }
    return 0;
}