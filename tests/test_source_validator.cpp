#include <catch2/catch_test_macros.hpp>
#include <core/SourceValidator.h>
#include <core/Identity.h>
#include <config/Config.h>
#include <unordered_map>

TEST_CASE("SourceValidator - empty source fails by default", "[source_validator]") {
    SourceValidator validator;
    std::unordered_map<std::string, Identity> empty;

    auto result = validator.validate(empty, "Test");
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "VALIDATION_EMPTY");
}

TEST_CASE("SourceValidator - empty source allowed when configured", "[source_validator]") {
    SourceValidationConfig config;
    config.allowEmpty = true;
    SourceValidator validator(config);

    std::unordered_map<std::string, Identity> empty;
    auto result = validator.validate(empty, "Test");

    REQUIRE(result.hasValue());
    REQUIRE(result.value().validRows == 0);
    REQUIRE(!result.value().warnings.empty());
}

TEST_CASE("SourceValidator - valid source passes", "[source_validator]") {
    SourceValidator validator;
    std::unordered_map<std::string, Identity> identities = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } }
    };

    auto result = validator.validate(identities, "HR");
    REQUIRE(result.hasValue());
    REQUIRE(result.value().validRows == 2);
}

TEST_CASE("SourceValidator - empty ID is error", "[source_validator]") {
    SourceValidator validator;
    std::unordered_map<std::string, Identity> identities = {
        { "", { "", "Alice", "Engineering" } }
    };

    auto result = validator.validate(identities, "HR");
    REQUIRE(result.hasError());
}

TEST_CASE("SourceValidator - size constraints work", "[source_validator]") {
    SourceValidationConfig config;
    config.minExpectedSize = 5;
    config.maxExpectedSize = 10;
    SourceValidator validator(config);

    std::unordered_map<std::string, Identity> small = {
        { "1", { "1", "A", "X" } },
        { "2", { "2", "B", "Y" } }
    };

    auto result = validator.validate(small, "Test");
    REQUIRE(result.hasValue());
    REQUIRE(!result.value().warnings.empty());
}

TEST_CASE("SourceValidator - validateHeaders checks required columns", "[source_validator]") {
    SourceValidator validator;

    std::vector<std::string> validHeaders = {"id", "name", "department"};
    REQUIRE(validator.validateHeaders(validHeaders).hasValue());

    std::vector<std::string> missingDept = {"id", "name"};
    auto result = validator.validateHeaders(missingDept);
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "VALIDATION_SCHEMA");
}

TEST_CASE("SourceValidator - fromConfig returns default config", "[source_validator]") {
    Config cfg; // real config with defaults
    auto result = SourceValidator::fromConfig(cfg);
    REQUIRE(result.hasValue());
    REQUIRE(result.value().requiredColumns.size() == 3);
    REQUIRE(result.value().allowEmpty == false);
    REQUIRE(result.value().maxMalformedRatio == 0.05);
    REQUIRE(result.value().maxDuplicateRows == 0);
}

TEST_CASE("SourceValidator - duplicate detection fails when maxDuplicateRows=0", "[source_validator]") {
    SourceValidationConfig config;
    config.maxDuplicateRows = 0; // fail on any duplicate
    SourceValidator validator(config);

    std::unordered_map<std::string, Identity> identities = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } }
    };

    // Pass duplicateRows=1 to simulate CSV parser finding 1 duplicate
    auto result = validator.validate(identities, "HR", 3, 0, 1);
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "VALIDATION_FAILED");
    REQUIRE(result.error().message.find("duplicate IDs") != std::string::npos);
}

TEST_CASE("SourceValidator - duplicate allowed up to threshold", "[source_validator]") {
    SourceValidationConfig config;
    config.maxDuplicateRows = 2; // allow up to 2 duplicates
    SourceValidator validator(config);

    std::unordered_map<std::string, Identity> identities = {
        { "101", { "101", "Alice", "Engineering" } }
    };

    // 2 duplicates should be allowed
    auto result = validator.validate(identities, "HR", 3, 0, 2);
    REQUIRE(result.hasValue());

    // 3 duplicates should fail
    result = validator.validate(identities, "HR", 4, 0, 3);
    REQUIRE(result.hasError());
}

TEST_CASE("SourceValidator - malformed ratio enforcement (5% default)", "[source_validator]") {
    SourceValidationConfig config;
    config.maxMalformedRatio = 0.05; // 5%
    SourceValidator validator(config);

    std::unordered_map<std::string, Identity> identities = {
        { "101", { "101", "Alice", "Engineering" } }
    };

    // 1 malformed out of 100 = 1% - should pass
    auto result = validator.validate(identities, "HR", 100, 1, 0);
    REQUIRE(result.hasValue());

    // 6 malformed out of 100 = 6% - should fail
    result = validator.validate(identities, "HR", 100, 6, 0);
    REQUIRE(result.hasError());
    REQUIRE(result.error().message.find("malformed rows") != std::string::npos);
}

TEST_CASE("SourceValidator - parse statistics reported in result", "[source_validator]") {
    SourceValidationConfig config;
    SourceValidator validator(config);

    std::unordered_map<std::string, Identity> identities = {
        { "101", { "101", "Alice", "Engineering" } },
        { "102", { "102", "Bob", "Sales" } }
    };

    // Well-formed source: no errors, no warnings, counts echoed back
    auto result = validator.validate(identities, "HR", 2, 0, 0);
    REQUIRE(result.hasValue());
    REQUIRE(result.value().totalRows == 2);
    REQUIRE(result.value().validRows == 2);
    REQUIRE(result.value().malformedRows == 0);
    REQUIRE(result.value().duplicateRows == 0);
    REQUIRE(result.value().warnings.empty());
}

TEST_CASE("SourceValidator - oversized source warns", "[source_validator]") {
    SourceValidationConfig config;
    config.maxExpectedSize = 10;
    SourceValidator validator(config);

    std::unordered_map<std::string, Identity> target;
    for (int i = 0; i < 100; ++i) {
        target[std::to_string(i)] = Identity{std::to_string(i), "User", "Dept"};
    }

    auto result = validator.validate(target, "Target", 100, 0, 0);
    REQUIRE(result.hasValue());
    REQUIRE(!result.value().warnings.empty());
}