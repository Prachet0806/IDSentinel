#pragma once
#include "core/Result.h"
#include "core/Identity.h"
#include <unordered_map>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

struct SourceValidationConfig {
    std::vector<std::string> requiredColumns = {"id", "name", "department"};
    double maxMalformedRatio = 0.05;  // 5% default
    size_t maxDuplicateRows = 0;      // 0 = fail on any duplicate
    std::optional<size_t> minExpectedSize;
    std::optional<size_t> maxExpectedSize;
    bool checkFreshness = false;
    std::optional<std::chrono::system_clock::time_point> maxAge;
    bool allowEmpty = false;
};

struct SourceValidationResult {
    size_t totalRows = 0;
    size_t validRows = 0;
    size_t malformedRows = 0;
    size_t duplicateRows = 0;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

class SourceValidator {
public:
    explicit SourceValidator(const SourceValidationConfig& config = {});

    Result<SourceValidationResult> validate(
        const std::unordered_map<std::string, Identity>& identities,
        const std::string& sourceName,
        size_t totalRows = 0,
        size_t malformedRows = 0,
        size_t duplicateRows = 0
    ) const;

    Result<void> validateHeaders(const std::vector<std::string>& headers) const;

    static Result<SourceValidationConfig> fromConfig(const struct Config& cfg);

private:
    SourceValidationConfig config_;
    bool hasRequiredColumns(const std::vector<std::string>& headers) const;
};