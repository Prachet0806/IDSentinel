#include "CLI.h"
#include "config/Config.h"
#include "core/Reconciler.h"
#include "core/Logging.h"
#include "core/SourceValidator.h"
#include "parsers/CSVParser.h"
#include "persistence/ComplianceStore.h"
#include "connectors/NetworkConnector.h"
#include "core/ProcessLock.h"
#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <memory>
#include <chrono>
#include <optional>
#include <nlohmann/json.hpp>
#include <fmt/core.h>
#include <format>
#include <sqlite3.h>
#include <iostream>
#include <cstdint>
#include <limits>

namespace {
constexpr int kBase64LineBlock = 4;
constexpr int kBase64ByteBlock = 3;
constexpr int kHexFieldWidth = 2;
constexpr int kBitsPerByte = 8;

std::string base64Encode(const uint8_t* data, size_t len) {
    if (len > static_cast<size_t>((std::numeric_limits<int>::max)())) {
        throw std::length_error("base64 input too large");
    }
    std::string out;
    const size_t encodedSize = static_cast<size_t>(kBase64LineBlock) *
        ((len + static_cast<size_t>(kBase64ByteBlock - 1)) / static_cast<size_t>(kBase64ByteBlock));
    out.resize(encodedSize + 1); // EVP_EncodeBlock writes a terminating NUL.
    const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data, static_cast<int>(len));
    if (written < 0) throw std::runtime_error("Base64 encoding failed");
    out.resize(static_cast<size_t>(written));
    return out;
}

std::string hexEncode(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(kHexFieldWidth) << static_cast<int>(data[i]);
    }
    return oss.str();
}

void printConfig(const Config& cfg) {
    fmt::print("Network:\n");
    fmt::print("  hr_feed_url: {}\n", redactUrlForLogging(cfg.network.hrFeedUrl));
    fmt::print("  timeout_seconds: {}\n", cfg.network.timeoutSeconds);
    fmt::print("  ca_bundle_path: {}\n", cfg.network.caBundlePath.empty() ? "(system default)" : redactUrlForLogging(cfg.network.caBundlePath));
    fmt::print("\nDatabase:\n");
    fmt::print("  path: {}\n", cfg.database.path.string());
    fmt::print("  wal_mode: {}\n", cfg.database.walMode ? "true" : "false");
    fmt::print("  busy_timeout_ms: {}\n", cfg.database.busyTimeoutMs);
    fmt::print("\nPolicy:\n");
    fmt::print("  orphan_severity: {}\n", toString(cfg.policy.orphanSeverity));
    fmt::print("  missing_severity: {}\n", toString(cfg.policy.missingSeverity));
    fmt::print("  drift_severity: {}\n", toString(cfg.policy.driftSeverity));
    fmt::print("\nSource:\n");
    fmt::print("  max_file_age_hours: {}\n", cfg.source.maxFileAgeHours);
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

Result<CLIOptions> parseCLI(int argc, char* argv[]) { // NOLINT(readability-function-cognitive-complexity): one straight-line block per subcommand; no nesting to extract
    CLIOptions opts;
    CLI::App app("IDSentinel - Identity Reconciliation Engine");
    constexpr int kMaxInspectLimit = 10000; // NOLINT(readability-magic-numbers): CLI page-size cap
    constexpr int kHmacKeyBits = 256; // NOLINT(readability-magic-numbers): HMAC-SHA256 key size

    auto* reconcile = app.add_subcommand("reconcile", "Run identity reconciliation (default)");
    reconcile->add_flag("--dry-run", opts.dryRun, "Preview violations without writing to database");
    reconcile->add_flag("--allow-empty-target", opts.allowEmptyTarget,
                        "Allow empty target source (WARNING: may produce mass false-positive missing accounts)");
    reconcile->add_flag("--allow-local-fallback", opts.allowLocalFallback,
                        "Allow fallback to local CSV file when network fetch fails (opt-in)");
    reconcile->add_option("--config", opts.configPath, "Path to config file");

    auto* inspect = app.add_subcommand("inspect", "Inspect reconciliation run results");
    inspect->add_option("--run-id", opts.runId, "Run ID to inspect")->required();
    inspect->add_option("--format", opts.inspectFormat, "Output format: table, json")->check(CLI::IsMember({"table", "json"}));
    inspect->add_option("--limit", opts.inspectLimit, "Max findings per page")->check(CLI::Range(1, kMaxInspectLimit));
    inspect->add_option("--offset", opts.inspectOffset, "Findings page offset")->check(CLI::NonNegativeNumber);
    inspect->add_option("--config", opts.configPath, "Path to config file");

    auto* configCmd = app.add_subcommand("config", "Show or validate configuration");
    configCmd->add_flag("--validate", opts.validateOnly, "Validate config and exit");
    configCmd->add_option("--config", opts.configPath, "Path to config file");

    auto* keygen = app.add_subcommand("keygen", "Generate HMAC key");
    keygen->add_option("--bits", opts.keyBits, "Key size in bits")->check(CLI::IsMember({kHmacKeyBits}));
    keygen->add_option("--format", opts.keyFormat, "Output format")->check(CLI::IsMember({"base64", "hex"}));

    auto* verify = app.add_subcommand("verify", "Verify hash chain integrity of a reconciliation run");
    verify->add_option("--run-id", opts.verifyRunId, "Run ID to verify")->required();
    verify->add_option("--hmac-key", opts.verifyHmacKey, "HMAC key (base64) for verification");
    verify->add_option("--config", opts.configPath, "Path to config file");

    app.set_config("--config", "", "Config file", false);
    app.require_subcommand(0, 1);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        if (e.get_exit_code() == 0) {
            app.exit(e);
            return Result<CLIOptions>::err(Error{"CLI_HELP", "help displayed"});
        }
        return Result<CLIOptions>::err(Error{ "CLI_PARSE", e.what() });
    } catch (const std::exception& e) {
        return Result<CLIOptions>::err(Error{ "CLI_PARSE_EXCEPTION", e.what() });
    } catch (...) {
        return Result<CLIOptions>::err(Error{ "CLI_PARSE_EXCEPTION", "Unknown exception during CLI parsing" });
    }

    if (app.get_subcommands().empty()) {
        opts.command = CLIOptions::Command::Reconcile;
    } else {
        const std::string& cmd = app.get_subcommands()[0]->get_name();
        if (cmd == "reconcile") opts.command = CLIOptions::Command::Reconcile;
        else if (cmd == "inspect") opts.command = CLIOptions::Command::Inspect;
        else if (cmd == "config") opts.command = CLIOptions::Command::Config;
        else if (cmd == "keygen") opts.command = CLIOptions::Command::Keygen;
        else if (cmd == "verify") opts.command = CLIOptions::Command::Verify;
    }

    return Result<CLIOptions>::ok(opts);
}

int runReconcile(const CLIOptions& opts) { // NOLINT(readability-function-cognitive-complexity): fail-closed orchestration is intentionally sequential; phases are logged inline
    auto cfgResult = loadConfig(opts.configPath);
    if (cfgResult.hasError()) {
        SPDLOG_ERROR("Failed to load config: {}", cfgResult.error().message);
        return 1;
    }
    Config cfg = std::move(cfgResult.value());

    if (!opts.dryRun && cfg.security.hmacKey.empty()) {
        std::cerr << "A 256-bit HMAC key is required for a durable reconciliation run. Set IDSENTINEL_SECURITY__HMAC_KEY.\n";
        return 1;
    }

    initLogging(cfg.logging.format, cfg.logging.level,
                opts.dryRun ? std::optional<std::filesystem::path>{} : std::optional<std::filesystem::path>{cfg.logging.file},
                cfg.logging.maxFileSizeMb, cfg.logging.maxFiles, cfg.logging.dailyRotation);

    SPDLOG_INFO("Starting IDSentinel reconciliation");

    // Fetch HR feed
    NetworkConnector net;
    net.setTimeouts(cfg.network.timeoutSeconds, cfg.network.timeoutSeconds);
    constexpr size_t kBytesPerMb = size_t{1024} * 1024; // NOLINT(readability-magic-numbers): MiB to bytes
    net.setMaxResponseBytes(static_cast<size_t>(cfg.network.maxResponseMb) * kBytesPerMb);
    net.setMaxRetries(cfg.network.maxRetries);
    if (!cfg.network.caBundlePath.empty()) {
        net.setCABundle(cfg.network.caBundlePath);
    }

    SPDLOG_INFO("Fetching HR feed from: {}", redactUrlForLogging(cfg.network.hrFeedUrl));
    auto hrResult = net.fetch(cfg.network.hrFeedUrl);
    std::string hrCsv;
    if (hrResult.hasError()) {
        if (opts.allowLocalFallback) {
            SPDLOG_WARN("Network fetch failed: {}. Falling back to local cache.", hrResult.error().message);
        } else {
            SPDLOG_ERROR("Network fetch failed: {}. Local fallback disabled (use --allow-local-fallback to enable).", hrResult.error().message);
            return 1;
        }
    } else {
        hrCsv = std::move(hrResult.value());
    }

    // Check for empty response (204 No Content or empty body)
    if (!hrResult.hasError() && hrCsv.empty()) {
        if (opts.allowLocalFallback) {
            SPDLOG_WARN("HR feed response is empty. Falling back to local cache.");
        } else {
            SPDLOG_ERROR("HR feed response is empty (204 No Content or empty body). Local fallback disabled (use --allow-local-fallback to enable).");
            return 1;
        }
    }

    // Parse HR
    std::unordered_map<std::string, Identity> hrIdentities;
    CSVParseResult hrParseResult;
    if (!hrCsv.empty()) {
        auto parseResult = CSVParser::parse(hrCsv);
        if (parseResult.hasError()) {
            SPDLOG_ERROR("Failed to parse HR feed: {}", parseResult.error().message);
            return 1;
        }
        hrParseResult = std::move(parseResult.value());
        hrIdentities = std::move(hrParseResult.identities);
    }

    auto checkFreshness = [&](const std::filesystem::path& path, const std::string& sourceName) -> bool {
        if (cfg.source.maxFileAgeHours <= 0) return true;
        std::error_code ec;
        auto mtime = std::filesystem::last_write_time(path, ec);
        if (ec) {
            SPDLOG_ERROR("Cannot stat {} source file: {}", sourceName, ec.message());
            return false;
        }
        using namespace std::chrono;
        auto age = duration_cast<hours>(file_clock::now() - mtime);
        if (age.count() > cfg.source.maxFileAgeHours) {
            SPDLOG_CRITICAL("{} source file is {}h old (max allowed: {}h). Aborting reconciliation.",
                            sourceName, age.count(), cfg.source.maxFileAgeHours);
            return false;
        }
        return true;
    };

    if (hrIdentities.empty()) {
        if (!opts.allowLocalFallback) {
            SPDLOG_CRITICAL("HR feed contains no valid identities; local fallback disabled.");
            return 1;
        }
        // Fallback to local file (streamed from disk)
        std::filesystem::path localPath = cfg.source.hrFallbackPath;
        if (localPath.empty()) {
            SPDLOG_CRITICAL("Local HR fallback requested but source.hr_fallback_path is not configured.");
            return 1;
        }
        if (std::filesystem::exists(localPath)) {
            SPDLOG_WARN("Using local HR fallback file: {}", localPath.string());
            if (!checkFreshness(localPath, "HR")) return 1;
            auto parseResult = CSVParser::parseFile(localPath);
            if (parseResult.hasError()) {
                SPDLOG_ERROR("Failed to parse local HR feed: {}", parseResult.error().message);
                return 1;
            }
            hrParseResult = std::move(parseResult.value());
            hrIdentities = std::move(hrParseResult.identities);
        }
    }

    if (hrIdentities.empty()) {
        SPDLOG_CRITICAL("No valid HR data available. Aborting reconciliation.");
        return 1;
    }
    SPDLOG_INFO("Loaded {} HR identities (total rows: {}, malformed: {}, duplicates: {})",
                hrIdentities.size(), hrParseResult.totalRows, hrParseResult.malformedRows, hrParseResult.duplicateRows);

    // Load system dump
    std::filesystem::path systemPath = cfg.source.targetPath;
    if (systemPath.empty()) {
        SPDLOG_CRITICAL("Target source path is not configured (source.target_path).");
        return 1;
    }
    if (!std::filesystem::exists(systemPath)) {
        SPDLOG_CRITICAL("System dump not found: {}", systemPath.string());
        return 1;
    }

    if (!checkFreshness(systemPath, "Target")) return 1;

    auto sysParseResultRaw = CSVParser::parseFile(systemPath);
    if (sysParseResultRaw.hasError()) {
        SPDLOG_ERROR("Failed to parse system dump: {}", sysParseResultRaw.error().message);
        return 1;
    }

    CSVParseResult sysParseResult = std::move(sysParseResultRaw.value());
    auto systemIdentities = std::move(sysParseResult.identities);
    SPDLOG_INFO("Loaded {} system identities (total rows: {}, malformed: {}, duplicates: {})",
                systemIdentities.size(), sysParseResult.totalRows, sysParseResult.malformedRows, sysParseResult.duplicateRows);

    // Source validation (fail-closed)
    constexpr double kMaxMalformedRatio = 0.05; // NOLINT(readability-magic-numbers): 5% malformed-row tolerance
    SourceValidationConfig hrValidatorConfig = SourceValidationConfig{
        .requiredColumns = {"id", "name", "department"},
        .maxMalformedRatio = kMaxMalformedRatio,
        .maxDuplicateRows = 0,
        .minExpectedSize = std::nullopt,
        .maxExpectedSize = std::nullopt,
        .checkFreshness = false,
        .maxAge = std::nullopt,
        .allowEmpty = false
    };
    SourceValidator hrValidator(hrValidatorConfig);
    auto hrValidation = hrValidator.validate(hrIdentities, "HR",
                                             hrParseResult.totalRows,
                                             hrParseResult.malformedRows,
                                             hrParseResult.duplicateRows);
    if (hrValidation.hasError()) {
        SPDLOG_CRITICAL("HR source validation failed: {}", hrValidation.error().message);
        return 1;
    }
    for (const auto& warning : hrValidation.value().warnings) {
        SPDLOG_WARN("HR source: {}", warning);
    }

    SourceValidationConfig targetValidatorConfig = SourceValidationConfig{
        .requiredColumns = {"id", "name", "department"},
        .maxMalformedRatio = kMaxMalformedRatio,
        .maxDuplicateRows = 0,
        .minExpectedSize = std::nullopt,
        .maxExpectedSize = std::nullopt,
        .checkFreshness = false,
        .maxAge = std::nullopt,
        .allowEmpty = opts.allowEmptyTarget
    };
    SourceValidator targetValidator(targetValidatorConfig);
    auto targetValidation = targetValidator.validate(systemIdentities, "Target",
                                                     sysParseResult.totalRows,
                                                     sysParseResult.malformedRows,
                                                     sysParseResult.duplicateRows);
    if (targetValidation.hasError()) {
        SPDLOG_CRITICAL("Target source validation failed: {}", targetValidation.error().message);
        return 1;
    }
    for (const auto& warning : targetValidation.value().warnings) {
        SPDLOG_WARN("Target source: {}", warning);
    }

    // Target-source size sanity check - fail closed if ratio outside expected range
    constexpr double kMaxSizeRatio = 10.0; // NOLINT(readability-magic-numbers): order-of-magnitude sanity bound
    constexpr double kMinSizeRatio = 0.1; // NOLINT(readability-magic-numbers): order-of-magnitude sanity bound
    if (!hrIdentities.empty() && !systemIdentities.empty()) {
        // NOLINTNEXTLINE(clang-diagnostic-implicit-int-float-conversion): identity counts are well below 2^53, exactly representable as double
        double ratio = static_cast<double>(systemIdentities.size()) / static_cast<double>(hrIdentities.size());
        if (ratio > kMaxSizeRatio || ratio < kMinSizeRatio) {
            SPDLOG_CRITICAL("Target/HR size ratio {:.2f} outside expected range [0.1, 10.0]. Aborting.", ratio);
            return 1;
        }
    }

    if (opts.allowEmptyTarget && systemIdentities.empty()) {
        SPDLOG_WARN("WARNING: empty target explicitly allowed");
        SPDLOG_WARN("WARNING: all HR identities may be classified as missing");
        fmt::print("\nWARNING: empty target explicitly allowed\n");
        fmt::print("WARNING: all HR identities may be classified as missing\n\n");
    }

    // Single-writer policy: concurrent runs could interleave ledger writes.
    // The lock is held until runReconcile returns (skip in dry-run: no writes).
    std::optional<ProcessLock> dbLock;
    if (!opts.dryRun) {
        std::filesystem::path lockPath = cfg.database.path;
        lockPath += ".lock";
        dbLock.emplace(lockPath);
        auto lockResult = dbLock->tryAcquire();
        if (lockResult.hasError()) {
            SPDLOG_ERROR("Failed to acquire database lock: {}", lockResult.error().message);
            return 1;
        }
        if (!lockResult.value()) {
            SPDLOG_CRITICAL("Another IDSentinel instance is running (lock held). Refusing to start.");
            return 1;
        }
    }

    // Initialize database (skip in dry-run mode)
    std::unique_ptr<ComplianceStore> store;
    if (!opts.dryRun) {
        store = std::make_unique<ComplianceStore>(cfg.database.path, cfg.database.walMode, cfg.database.busyTimeoutMs);
        if (auto r = store->openForWrite(); r.hasError()) {
            SPDLOG_ERROR("Failed to open database for writing: {}", r.error().message);
            return 1;
        }
    }

    // Run reconciliation
    Reconciler reconciler(store.get(), cfg.security.hmacKey, &cfg.policy);
    auto mode = opts.dryRun ? Reconciler::RunMode::DryRun : Reconciler::RunMode::Normal;
    auto result = reconciler.runReconciliation(hrIdentities, systemIdentities, mode);

    if (result.hasError()) {
        SPDLOG_ERROR("Reconciliation failed: {}", result.error().message);
        return 1;
    }

    const auto& res = result.value();
    SPDLOG_INFO("\nReconciliation Summary:");
    SPDLOG_INFO("  Run ID: {}", res.runId);
    SPDLOG_INFO("  Orphan Accounts: {}", res.orphanCount);
    SPDLOG_INFO("  Missing Accounts: {}", res.missingCount);
    SPDLOG_INFO("  Attribute Drift: {}", res.driftCount);
    SPDLOG_INFO("  Status: {}", res.success ? "SUCCESS" : "FAILED");

    if (opts.dryRun) {
        SPDLOG_INFO("\n[DRY-RUN] No changes written to database.");
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
    if (auto r = store.openReadOnly(); r.hasError()) {
        SPDLOG_ERROR("Failed to open database read-only: {}", r.error().message);
        return 1;
    }
    IComplianceQueryStore& query = store;

    // I10: a nonexistent run and a run with zero findings are different facts.
    auto existsResult = query.runExists(opts.runId);
    if (existsResult.hasError()) {
        SPDLOG_ERROR("Failed to query run: {}", existsResult.error().message);
        return 1;
    }
    if (!existsResult.value()) {
        SPDLOG_ERROR("Run not found: {}", opts.runId);
        std::cerr << "Run not found: " << opts.runId << "\n";
        return 1;
    }

    auto runResult = query.getRun(opts.runId);
    if (runResult.hasError()) {
        SPDLOG_ERROR("Failed to load run: {}", runResult.error().message);
        return 1;
    }
    const RunInfo& run = runResult.value();

    auto countResult = query.countFindings(opts.runId);
    if (countResult.hasError()) {
        SPDLOG_ERROR("Failed to count findings: {}", countResult.error().message);
        return 1;
    }
    int total = countResult.value();

    auto findingsResult = query.queryFindings(opts.runId, opts.inspectLimit, opts.inspectOffset);
    if (findingsResult.hasError()) {
        SPDLOG_ERROR("Failed to query findings: {}", findingsResult.error().message);
        return 1;
    }
    const auto& findings = findingsResult.value();

    if (opts.inspectFormat == "json") {
        nlohmann::json out;
        out["run_id"] = run.runId;
        out["status"] = std::string(toString(run.status));
        out["total_violations"] = run.totalViolations;
        out["finding_count"] = total;
        out["limit"] = opts.inspectLimit;
        out["offset"] = opts.inspectOffset;
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& f : findings) {
            nlohmann::json j;
            j["finding_id"] = f.findingId;
            j["run_id"] = f.runId;
            j["user_id"] = f.userId;
            j["violation_type"] = std::string(toString(f.type));
            j["severity"] = std::string(toString(f.severity));
            j["detected_at"] = f.detectedAt;
            j["status"] = std::string(toString(f.status));
            j["integrity_hash"] = f.integrityHash;
            arr.emplace_back(std::move(j));
        }
        out["findings"] = arr;
        std::cout << out.dump(2, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
    } else {
        std::cout << std::format("Run: {}  Status: {}  Findings: {} (showing {} starting at offset {})\n",
            run.runId, toString(run.status), total,
            static_cast<int>(findings.size()), opts.inspectOffset);
        std::cout << std::format("{:<12} {:<20} {:<15} {:<18} {:<10} {:<20} {:<12} {}\n",
            "Finding ID", "Run ID", "User ID", "Violation Type", "Severity", "Detected At", "Status", "Integrity Hash");
        std::cout << std::format("{:-<12} {:-<20} {:-<15} {:-<18} {:-<10} {:-<20} {:-<12} {:-<64}\n", "", "", "", "", "", "", "", "");

        for (const auto& f : findings) {
            std::cout << std::format("{:<12} {:<20} {:<15} {:<18} {:<10} {:<20} {:<12} {}\n",
                f.findingId, f.runId, f.userId,
                toString(f.type), toString(f.severity),
                f.detectedAt, toString(f.status), f.integrityHash);
        }
        if (findings.empty()) {
            std::cout << "(no findings in this page; run has " << total << " total)\n";
        }
    }
    return 0;
}

int runConfig(const CLIOptions& opts) {
    auto cfgResult = loadConfig(opts.configPath);
    if (cfgResult.hasError()) {
        std::cerr << "Config validation failed: " << cfgResult.error().message << "\n";
        return 1;
    }
    Config cfg = std::move(cfgResult.value());

    if (opts.validateOnly) {
        std::cout << "Config validation passed.\n";
        return 0;
    }

    printConfig(cfg);
    return 0;
}

int runKeygen(const CLIOptions& opts) {
    if (opts.keyBits <= 0 || opts.keyBits % kBitsPerByte != 0) {
        std::cerr << "Invalid key size\n";
        return 1;
    }
    std::vector<uint8_t> key(static_cast<size_t>(opts.keyBits / kBitsPerByte));
    if (key.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) {
        std::cerr << "Key size too large\n";
        return 1;
    }
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        std::cerr << "Failed to generate random key\n";
        return 1;
    }

    std::string output;
    if (opts.keyFormat == "base64") {
        output = base64Encode(key.data(), key.size());
    } else {
        output = hexEncode(key.data(), key.size());
    }
    // Ensure no embedded NUL bytes in output
    output.erase(std::remove(output.begin(), output.end(), '\0'), output.end());
    std::cout << output << "\n";
    return 0;
}

int runVerify(const CLIOptions& opts) { // NOLINT(readability-function-cognitive-complexity): sequential verify pipeline; each block returns early on error
    // NOTE: never log key material. Only whether a key was supplied.
    SPDLOG_DEBUG("runVerify started for run: {}", opts.verifyRunId);
    try {
        auto cfgResult = loadConfig(opts.configPath);
        if (cfgResult.hasError()) {
            std::cerr << "Config validation failed: " << cfgResult.error().message << "\n";
            return 1;
        }
        Config cfg = std::move(cfgResult.value());

        initLogging(cfg.logging.format, cfg.logging.level, cfg.logging.file,
                    cfg.logging.maxFileSizeMb, cfg.logging.maxFiles, cfg.logging.dailyRotation);

        SPDLOG_INFO("Verifying signed manifest for run: {}", opts.verifyRunId);

        ComplianceStore store(cfg.database.path);
        if (auto r = store.openReadOnly(); r.hasError()) {
            SPDLOG_ERROR("Failed to open database read-only: {}", r.error().message);
            return 1;
        }
        IComplianceQueryStore& query = store;

        // Check if run exists
        auto existsResult = query.runExists(opts.verifyRunId);
        if (existsResult.hasError()) {
            SPDLOG_ERROR("Failed to query run: {}", existsResult.error().message);
            return 1;
        }
        if (!existsResult.value()) {
            SPDLOG_ERROR("Run not found: {}", opts.verifyRunId);
            std::cerr << "Run not found: " << opts.verifyRunId << "\n";
            return 1;
        }

        // Get run info (existence already confirmed above; load validates readability)
        auto runResult = query.getRun(opts.verifyRunId);
        if (runResult.hasError()) {
            SPDLOG_ERROR("Failed to load run: {}", runResult.error().message);
            return 1;
        }
        if (runResult.value().status != RunStatus::Success) {
            std::cerr << "Only completed successful runs can be verified.\n";
            return 1;
        }

        // Get all findings for this run
        auto countResult = query.countFindings(opts.verifyRunId);
        if (countResult.hasError()) {
            SPDLOG_ERROR("Failed to count findings: {}", countResult.error().message);
            return 1;
        }
        int total = countResult.value();

        auto findingsResult = query.queryFindings(opts.verifyRunId, total, 0);
        if (findingsResult.hasError()) {
            SPDLOG_ERROR("Failed to query findings: {}", findingsResult.error().message);
            return 1;
        }
        const auto& findings = findingsResult.value();

        auto manifestResult = query.getRunManifest(opts.verifyRunId);
        if (manifestResult.hasError()) {
            std::cerr << "Cannot load run manifest: " << manifestResult.error().message << "\n";
            return 1;
        }
        const auto& maybeManifest = manifestResult.value();
        if (!maybeManifest.has_value()) {
            std::cerr << "Run has no signed manifest and cannot be verified.\n";
            return 1;
        }
        const auto& manifest = *maybeManifest;
        if (manifest.expectedCount != total || static_cast<int>(findings.size()) != total ||
            runResult.value().totalViolations != total) {
            std::cerr << "Run manifest count does not match stored findings.\n";
            return 1;
        }

        // Determine HMAC key to use for verification (never log the value).
        std::string hmacKey;
        if (opts.verifyHmacKey.has_value() && !opts.verifyHmacKey.value().empty()) {
            hmacKey = opts.verifyHmacKey.value();
            SPDLOG_DEBUG("Using caller-supplied HMAC key for verification");
        } else {
            hmacKey = cfg.security.hmacKey;
            SPDLOG_DEBUG("Using configured HMAC key for verification (supplied: {})",
                         opts.verifyHmacKey.has_value() ? "yes" : "no");
        }
        if (hmacKey.empty()) {
            std::cerr << "A 256-bit HMAC key is required to verify a run.\n";
            return 1;
        }

        // Verify each finding's hash
        bool allValid = true;
        Reconciler reconciler(nullptr, hmacKey, &cfg.policy);
        std::vector<std::string> hashes;
        hashes.reserve(findings.size());

        SPDLOG_INFO("Verifying {} findings for run {}", findings.size(), opts.verifyRunId);
        std::cout << "Verifying " << findings.size() << " findings for run " << opts.verifyRunId << "...\n";
        
        try {
            for (size_t i = 0; i < findings.size(); ++i) {
                const auto& f = findings[i];
                hashes.push_back(f.integrityHash);
                
                std::string computedHash = reconciler.findingSignature(
                    opts.verifyRunId, f.userId, f.type, f.severity, f.detectedAt);
                
                if (computedHash.size() == f.integrityHash.size() &&
                    CRYPTO_memcmp(computedHash.data(), f.integrityHash.data(), computedHash.size()) == 0) {
                    std::cout << "  [" << (i + 1) << "/" << findings.size() << "] OK: " << f.userId
                              << " (" << std::string(toString(f.type)) << ", " << std::string(toString(f.severity)) << ")\n";
                } else {
                    std::cerr << "  [" << (i + 1) << "/" << findings.size() << "] FAIL: " << f.userId
                              << " (" << std::string(toString(f.type)) << ", " << std::string(toString(f.severity)) << ")\n"
                              << "    Expected: " << f.integrityHash << "\n"
                              << "    Computed: " << computedHash << "\n";
                    allValid = false;
                }
            }
        } catch (const std::exception& e) {
            SPDLOG_ERROR("Verification failed with exception: {}", e.what());
            return 1;
        } catch (...) {
            SPDLOG_ERROR("Verification failed with unknown exception");
            return 1;
        }

        const std::string computedManifest = reconciler.manifestSignature(opts.verifyRunId, hashes);
        if (computedManifest.size() != manifest.signature.size() ||
            CRYPTO_memcmp(computedManifest.data(), manifest.signature.data(), computedManifest.size()) != 0) {
            std::cerr << "Run manifest signature mismatch.\n";
            allValid = false;
        }

        if (allValid) {
            std::cout << "\nAll " << findings.size() << " findings verified successfully.\n";
            SPDLOG_INFO("Verification successful: all {} findings in run {} are valid", findings.size(), opts.verifyRunId);
            return 0;
        } else {
            std::cerr << "\nVerification FAILED: " << findings.size() << " findings checked, some failed.\n";
            SPDLOG_ERROR("Verification failed for run {}", opts.verifyRunId);
            return 1;
        }
    } catch (const std::exception& e) {
        SPDLOG_ERROR("Verify command failed: {}", e.what());
        return 1;
    } catch (...) {
        SPDLOG_ERROR("Verify command failed with unknown exception");
        return 1;
    }
}
