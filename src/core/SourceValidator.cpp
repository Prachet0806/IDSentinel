#include "SourceValidator.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <chrono>
#include <set>

SourceValidator::SourceValidator(const SourceValidationConfig& config)
    : config_(config) {}

Result<void> SourceValidator::validateHeaders(const std::vector<std::string>& headers) const {
    std::vector<std::string> missing;
    for (const auto& required : config_.requiredColumns) {
        bool found = false;
        for (const auto& header : headers) {
            if (header == required) {
                found = true;
                break;
            }
        }
        if (!found) {
            missing.emplace_back(required);
        }
    }

    if (!missing.empty()) {
        std::string msg = "Missing required columns: ";
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i > 0) msg += ", ";
            msg += missing[i];
        }
        return Result<void>::err(Error{ "VALIDATION_SCHEMA", msg });
    }
    return Result<void>::ok();
}

Result<SourceValidationResult> SourceValidator::validate( // NOLINT(readability-function-cognitive-complexity): sequential fail-closed checks, each returns/appends independently
    const std::unordered_map<std::string, Identity>& identities,
    const std::string& sourceName,
    size_t totalRows,
    size_t malformedRows,
    size_t duplicateRows
) const {
    SourceValidationResult result;
    result.totalRows = totalRows > 0 ? totalRows : identities.size();
    result.validRows = identities.size();
    result.malformedRows = malformedRows;
    result.duplicateRows = duplicateRows;

    if (identities.empty()) {
        if (!config_.allowEmpty) {
            result.errors.push_back(sourceName + " source is empty");
            return Result<SourceValidationResult>::err(Error{ "VALIDATION_EMPTY", result.errors[0] });
        }
        result.warnings.push_back(sourceName + " source is empty (allowed by config)");
        return Result<SourceValidationResult>::ok(result);
    }

    // Check duplicate threshold
    if (config_.maxDuplicateRows > 0 && duplicateRows > config_.maxDuplicateRows) {
        result.errors.push_back(
            sourceName + " source has " + std::to_string(duplicateRows) +
            " duplicate IDs (max allowed: " + std::to_string(config_.maxDuplicateRows) + ")"
        );
    } else if (config_.maxDuplicateRows == 0 && duplicateRows > 0) {
        result.errors.push_back(
            sourceName + " source has " + std::to_string(duplicateRows) +
            " duplicate IDs (duplicates not allowed)"
        );
    }

    // Check malformed ratio
    if (result.totalRows > 0) {
        constexpr double kPercentScale = 100.0; // NOLINT(readability-magic-numbers): ratio to percent
        // NOLINTNEXTLINE(clang-diagnostic-implicit-int-float-conversion): row counts are well below 2^53, exactly representable as double
        double malformedRatio = static_cast<double>(malformedRows) / static_cast<double>(result.totalRows);
        if (malformedRatio > config_.maxMalformedRatio) {
            result.errors.push_back(
                sourceName + " source has " + std::to_string(malformedRows) +
                " malformed rows out of " + std::to_string(result.totalRows) +
                " (" + std::to_string(static_cast<int>(malformedRatio * kPercentScale)) + "% > " +
                std::to_string(static_cast<int>(config_.maxMalformedRatio * kPercentScale)) + "% allowed)"
            );
        }
    }

    if (config_.minExpectedSize && identities.size() < *config_.minExpectedSize) {
        result.warnings.push_back(
            sourceName + " size " + std::to_string(identities.size()) +
            " below minimum expected " + std::to_string(*config_.minExpectedSize)
        );
    }
    if (config_.maxExpectedSize && identities.size() > *config_.maxExpectedSize) {
        result.warnings.push_back(
            sourceName + " size " + std::to_string(identities.size()) +
            " exceeds maximum expected " + std::to_string(*config_.maxExpectedSize)
        );
    }

    if (config_.checkFreshness && config_.maxAge) {
        result.warnings.push_back("Freshness check not yet implemented for " + sourceName);
    }

    for (const auto& [id, identity] : identities) {
        if (id.empty()) {
            result.errors.push_back("Empty identity ID found in " + sourceName);
        }
        if (identity.name.empty()) {
            result.warnings.push_back("Empty name for ID " + id + " in " + sourceName);
        }
    }

    if (!result.errors.empty()) {
        return Result<SourceValidationResult>::err(Error{ "VALIDATION_FAILED", result.errors[0] });
    }

    SPDLOG_DEBUG("Source validation passed for {}: {} identities", sourceName, identities.size());
    return Result<SourceValidationResult>::ok(result);
}

bool SourceValidator::hasRequiredColumns(const std::vector<std::string>& headers) const {
    for (const auto& required : config_.requiredColumns) {
        bool found = false;
        for (const auto& header : headers) {
            if (header == required) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

Result<SourceValidationConfig> SourceValidator::fromConfig(const struct Config& cfg) {
    constexpr double kDefaultMaxMalformedRatio = 0.05; // NOLINT(readability-magic-numbers): 5% malformed-row tolerance
    (void)cfg;
    SourceValidationConfig vconfig;
    vconfig.requiredColumns = {"id", "name", "department"};
    vconfig.maxMalformedRatio = kDefaultMaxMalformedRatio;
    vconfig.maxDuplicateRows = 0;
    vconfig.allowEmpty = false;
    return Result<SourceValidationConfig>::ok(vconfig);
}