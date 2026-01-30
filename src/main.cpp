#include <iostream>
#include "connectors/NetworkConnector.h"
#include "parsers/CSVParser.h"
#include "core/Reconciler.h"
#include "persistence/ComplianceStore.h"

int main() {
    std::cout << "[IDSentinel] Starting identity reconciliation...\n";

    // === 1. Fetch HR Feed (Authoritative Source) ===
    std::string hrUrl = "https://gist.githubusercontent.com/dummy/raw/hr_feed.csv";
    std::string hrCsv;
    std::unordered_map<std::string, Identity> hrIdentities;
    NetworkConnector net;

        // 1️⃣ Try network
    if (net.fetch(hrUrl, hrCsv)) {
        std::cout << "[INFO] HR feed fetched via network.\n";
        hrIdentities = CSVParser::parse(hrCsv);

        // 2️⃣ Validate parsed data
        if (hrIdentities.empty()) {
            std::cerr << "[WARN] Network HR feed invalid or empty. Falling back to local.\n";
            hrCsv = CSVParser::loadFromFile("data/hr_feed.csv");
            hrIdentities = CSVParser::parse(hrCsv);
        }
    } 
    // 3️⃣ Network failed → fallback
    else {
        std::cerr << "[WARN] Network fetch failed. Using local HR feed.\n";
        hrCsv = CSVParser::loadFromFile("data/hr_feed.csv");
        hrIdentities = CSVParser::parse(hrCsv);
    }

    // 4️⃣ Final validation (hard stop)
    if (hrIdentities.empty()) {
        std::cerr << "[FATAL] No valid HR data available. Aborting reconciliation.\n";
        return 1;
    }

    // === 2. Load System Dump ===
    std::string systemCsv = CSVParser::loadFromFile("data/system_dump.csv");
    if (systemCsv.empty()) {
        std::cerr << "[FATAL] System dump missing.\n";
        return 1;
    }

    // === 3. Parse CSVs ===
    std::unordered_map<std::string, Identity> systemIdentities = CSVParser::parse(systemCsv);
    if (systemIdentities.empty()) {
        std::cerr << "[FATAL] System dump invalid or empty. Aborting reconciliation.\n";
        return 1;
    }

    // === 4. Init Compliance Store ===
    ComplianceStore store("compliance.db");
    if (!store.init()) {
        std::cerr << "[ERROR] Failed to initialize database.\n";
        return 1;
    }

    // === 5. Reconcile ===
    Reconciler reconciler(store);
    if (!reconciler.runReconciliation(hrIdentities, systemIdentities)) {
        std::cerr << "[ERROR] Reconciliation failed.\n";
        return 1;
    }

    std::cout << "[IDSentinel] Reconciliation complete.\n";
    return 0;
}
