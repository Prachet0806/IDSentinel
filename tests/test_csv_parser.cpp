#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include <parsers/CSVParser.h>
#include <core/Identity.h>
#include <sstream>

TEST_CASE("CSVParser::parse - basic parsing", "[csv]") {
    std::string csv = "101,Alice Engineer,Engineering\n102,Bob Salesman,Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto identities = result.value();
    REQUIRE(identities.size() == 2);
    REQUIRE(identities["101"].name == "Alice Engineer");
    REQUIRE(identities["101"].department == "Engineering");
    REQUIRE(identities["102"].name == "Bob Salesman");
    REQUIRE(identities["102"].department == "Sales");
}

TEST_CASE("CSVParser::parse - header line skipped", "[csv]") {
    std::string csv = "id,name,department\n101,Alice,Engineering\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto identities = result.value();
    REQUIRE(identities.size() == 1);
    REQUIRE(identities["101"].name == "Alice");
}

TEST_CASE("CSVParser::parse - quoted fields", "[csv]") {
    std::string csv = "101,\"Alice, Jr.\",Engineering\n102,\"Bob \"\"The Boss\"\"\",Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto identities = result.value();
    REQUIRE(identities.size() == 2);
    REQUIRE(identities["101"].name == "Alice, Jr.");
    REQUIRE(identities["102"].name == "Bob \"The Boss\"");
}

TEST_CASE("CSVParser::parse - empty lines skipped", "[csv]") {
    std::string csv = "\n101,Alice,Engineering\n\n102,Bob,Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto identities = result.value();
    REQUIRE(identities.size() == 2);
}

TEST_CASE("CSVParser::parse - duplicate IDs", "[csv]") {
    std::string csv = "101,Alice,Engineering\n101,Bob,Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto identities = result.value();
    REQUIRE(identities.size() == 1);
    REQUIRE(identities["101"].name == "Bob");
}

TEST_CASE("CSVParser::parseStream - callback invoked per row", "[csv]") {
    std::string csv = "101,Alice,Engineering\n102,Bob,Sales\n";
    std::stringstream ss(csv);
    std::vector<std::vector<std::string>> rows;

    auto result = CSVParser::parseStream(ss, [&](const std::vector<std::string>& cols) {
        rows.push_back(cols);
    });

    REQUIRE(result.hasValue());
    REQUIRE(rows.size() == 2);
    REQUIRE(rows[0][0] == "101");
    REQUIRE(rows[0][1] == "Alice");
    REQUIRE(rows[1][0] == "102");
}

TEST_CASE("CSVParser::loadFromFile - missing file returns error", "[csv]") {
    auto result = CSVParser::loadFromFile("/nonexistent/path.csv");
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "FILE_OPEN");
}