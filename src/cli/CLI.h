#pragma once
#include "config/Config.h"
#include "core/Result.h"
#include <string>
#include <optional>
#include <filesystem>

struct CLIOptions {
    enum class Command { Reconcile, Inspect, Config, Keygen, Verify } command = Command::Reconcile;
    std::optional<std::filesystem::path> configPath;
    bool dryRun = false;
    bool allowEmptyTarget = false;
    bool allowLocalFallback = false;
    std::string runId;
    std::string inspectFormat = "table";
    int inspectLimit = 100; // NOLINT(readability-magic-numbers): default page size
    int inspectOffset = 0;
    int keyBits = 256; // NOLINT(readability-magic-numbers): HMAC-SHA256 default key size
    std::string keyFormat = "base64";
    bool validateOnly = false;
    std::string verifyRunId;
    std::optional<std::string> verifyHmacKey;
};

Result<CLIOptions> parseCLI(int argc, char* argv[]);
int runReconcile(const CLIOptions& opts);
int runInspect(const CLIOptions& opts);
int runConfig(const CLIOptions& opts);
int runKeygen(const CLIOptions& opts);
int runVerify(const CLIOptions& opts);