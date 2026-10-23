#pragma once
#include "core/Result.h"
#include <sqlite3.h>

// SchemaManager is the SOLE component responsible for schema creation and
// migration. ComplianceStore::openForWrite()/openReadOnly() establish the
// connection and then call into here; they must not contain any DDL
// themselves.
//
// Guarantees:
//  - migrate() is idempotent: safe to run on every startup.
//  - migrate() never drops historical tables. Unknown future schema
//    versions and legacy pre-split tables fail closed with an error,
//    leaving existing data untouched.
class SchemaManager {
public:
    static constexpr int kCurrentVersion = 2;

    // Bring an open write connection to kCurrentVersion inside a
    // transaction. Read-only connections must NOT call this.
    static Result<void> migrate(sqlite3* db);

    // Validate a read-only connection without changing schema or run state.
    static Result<void> validateReadOnly(sqlite3* db);

    // Returns the stamped schema version (0 when no version stamped yet).
    static Result<int> currentVersion(sqlite3* db);

private:
    static Result<void> exec(sqlite3* db, const std::string& sql, const std::string& context);
    static Result<bool> tableExists(sqlite3* db, const std::string& name);
};
