#include "cli/CLI.h"
#include "core/Logging.h"
#include "connectors/NetworkConnector.h"
#include <spdlog/spdlog.h>

int main(int argc, char* argv[]) {
    // Process-scoped libcurl state: must outlive every NetworkConnector.
    CurlGlobal curlGlobal;

    // Initialize minimal logging early for CLI parsing errors
    initLogging(LogFormat::Text, LogLevel::Warn, std::nullopt);

    auto optsResult = parseCLI(argc, argv);
    if (optsResult.hasError()) {
        return 1;
    }

    CLIOptions opts = std::move(optsResult.value());

    switch (opts.command) {
        case CLIOptions::Command::Reconcile:
            return runReconcile(opts);
        case CLIOptions::Command::Inspect:
            return runInspect(opts);
        case CLIOptions::Command::Config:
            return runConfig(opts);
        case CLIOptions::Command::Keygen:
            return runKeygen(opts);
    }

    return 1;
}