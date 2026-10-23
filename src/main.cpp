#include "cli/CLI.h"
#include "core/Logging.h"
#include "connectors/NetworkConnector.h"
#include <spdlog/spdlog.h>
#include <iostream>

int main(int argc, char* argv[]) {
    try {
    // Process-scoped libcurl state: must outlive every NetworkConnector.
    CurlGlobal curlGlobal;

    // Initialize minimal logging early for CLI parsing errors
    initLogging(LogFormat::Text, LogLevel::Warn, std::nullopt);

    auto optsResult = parseCLI(argc, argv);
    if (optsResult.hasError()) {
        if (optsResult.error().code == "CLI_HELP") return 0;
        std::cerr << "CLI parsing error: " << optsResult.error().message << "\n";
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
        case CLIOptions::Command::Verify:
            return runVerify(opts);
    }

    return 1;
    } catch (const std::exception& e) {
        std::cerr << "IDSentinel failed: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "IDSentinel failed: unknown error\n";
        return 1;
    }
}
