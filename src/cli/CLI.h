#pragma once
#include "config/Config.h"
#include "core/Result.h"
#include <string>
#include <optional>
#include <filesystem>

struct CLIOptions {
    enum class Command { Reconcile, Inspect, Config, Keygen } command = Command::Reconcile;
    std::optional<std::filesystem::path> configPath;
    bool dryRun = false;
    bool allowEmptyTarget = false;
    std::string runId;
    std::string inspectFormat = "table";
    int inspectLimit = 100;
    int inspectOffset = 0;
    int keyBits = 256;
    std::string keyFormat = "base64";
    bool validateOnly = false;
};

Result<CLIOptions> parseCLI(int argc, char* argv[]);
int runReconcile(const CLIOptions& opts);
int runInspect(const CLIOptions& opts);
int runConfig(const CLIOptions& opts);
int runKeygen(const CLIOptions& opts);