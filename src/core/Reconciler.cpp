//src/core/Reconciler.cpp
#include "Reconciler.h"
#include <iostream>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

// SHA-256 over the violation fields for tamper evidence
static std::string computeHash(const std::string& uid,
                               const std::string& type,
                               const std::string& severity) {
    std::string data = uid + "|" + type + "|" + severity;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), digest);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : digest) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

Reconciler::Reconciler(ComplianceStore& store)
    : db(store) {

    riskPolicy["ORPHAN_ACCOUNT"]  = "CRITICAL";
    riskPolicy["MISSING_ACCOUNT"] = "MEDIUM";
}

std::string Reconciler::generateRunID() {
    using namespace std::chrono;
    auto now = system_clock::now().time_since_epoch();
    auto nanos = duration_cast<nanoseconds>(now).count();
    std::mt19937_64 rng(static_cast<unsigned long long>(nanos));
    std::uniform_int_distribution<unsigned long long> dist;
    std::ostringstream oss;
    oss << "RUN_" << nanos << "_" << std::hex << dist(rng);
    return oss.str();
}

void Reconciler::runReconciliation(
    const std::unordered_map<std::string, Identity>& hrSource,
    const std::unordered_map<std::string, Identity>& targetSystem
) {
    if (hrSource.empty()) {
        std::cerr << "[FATAL] HR source empty. Abort.\n";
        return;
    }

    std::string runID = generateRunID();
    std::cout << "[INFO] Starting run " << runID << "\n";

    if (!db.startRun(runID, "HR_API", "TARGET_SYSTEM")) {
        std::cerr << "[ERROR] Unable to start run in database. Abort.\n";
        return;
    }
    if (!db.beginTransaction()) {
        std::cerr << "[ERROR] Unable to open transaction. Abort.\n";
        return;
    }

    bool success = true;

    // ORPHAN ACCOUNTS
    for (const auto& [id, sysUser] : targetSystem) {
        if (hrSource.find(id) == hrSource.end()) {
            std::string sev = riskPolicy["ORPHAN_ACCOUNT"];
            std::string hash = computeHash(id, "ORPHAN_ACCOUNT", sev);

            if (!db.logViolation({id, "ORPHAN_ACCOUNT", sev}, runID, hash)) {
                success = false;
                std::cerr << "[ERROR] Failed to persist orphan violation for user " << id << "\n";
                break;
            }
            std::cout << "[ALERT] Orphan: " << sysUser.name << "\n";
        }
    }

    // MISSING ACCOUNTS (skip if already failed)
    if (success) {
        for (const auto& [id, hrUser] : hrSource) {
            if (targetSystem.find(id) == targetSystem.end()) {
                std::string sev = riskPolicy["MISSING_ACCOUNT"];
                std::string hash = computeHash(id, "MISSING_ACCOUNT", sev);

                if (!db.logViolation({id, "MISSING_ACCOUNT", sev}, runID, hash)) {
                    success = false;
                    std::cerr << "[ERROR] Failed to persist missing-account violation for user " << id << "\n";
                    break;
                }
            }
        }
    }

    if (!success) {
        db.rollbackTransaction();
        db.completeRun(runID, "FAILED");
        std::cerr << "[ERROR] Run failed and was rolled back.\n";
        return;
    }

    if (!db.commitTransaction()) {
        db.rollbackTransaction();
        db.completeRun(runID, "FAILED");
        std::cerr << "[ERROR] Commit failed. Run rolled back.\n";
        return;
    }

    db.completeRun(runID, "SUCCESS");
    std::cout << "[SUCCESS] Run completed.\n";
}
