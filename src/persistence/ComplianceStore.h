#pragma once
#include <sqlite3.h>
#include <string>

/*
 * Immutable violation record inserted by the application.
 * All derived state (history, counters) is handled by DB triggers.
 */
struct ViolationRecord {
    std::string userID;
    std::string type;
    std::string severity;
};

class ComplianceStore {
public:
    explicit ComplianceStore(const std::string& dbPath);
    ~ComplianceStore();

    // Schema + triggers
    bool init();

    // Run lifecycle
    bool startRun(const std::string& runId,
                  const std::string& sourceSystem,
                  const std::string& targetSystem);

    bool completeRun(const std::string& runId,
                     const std::string& status);

    // Transaction control
    bool beginTransaction();
    bool commitTransaction();
    void rollbackTransaction();

    // Immutable insert
    bool logViolation(const ViolationRecord& record,
                      const std::string& runId,
                      const std::string& integrityHash);

private:
    sqlite3* db;
    std::string dbPath;
};
