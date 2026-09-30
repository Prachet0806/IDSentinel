#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include <parsers/CSVParser.h>
#include <core/Identity.h>
#include <sstream>
#include <fstream>
#include <filesystem>

TEST_CASE("CSVParser::parse - basic parsing", "[csv]") {
    std::string csv = "101,Alice Engineer,Engineering\n102,Bob Salesman,Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 2);
    REQUIRE(parseResult.identities["101"].name == "Alice Engineer");
    REQUIRE(parseResult.identities["101"].department == "Engineering");
    REQUIRE(parseResult.identities["102"].name == "Bob Salesman");
    REQUIRE(parseResult.identities["102"].department == "Sales");
    REQUIRE(parseResult.totalRows == 2);
    REQUIRE(parseResult.validRows == 2);
    REQUIRE(parseResult.malformedRows == 0);
    REQUIRE(parseResult.duplicateRows == 0);
}

TEST_CASE("CSVParser::parse - header line skipped", "[csv]") {
    std::string csv = "id,name,department\n101,Alice,Engineering\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 1);
    REQUIRE(parseResult.identities["101"].name == "Alice");
    REQUIRE(parseResult.totalRows == 1);
    REQUIRE(parseResult.validRows == 1);
}

TEST_CASE("CSVParser::parse - quoted fields", "[csv]") {
    std::string csv = "101,\"Alice, Jr.\",Engineering\n102,\"Bob \"\"The Boss\"\"\",Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 2);
    REQUIRE(parseResult.identities["101"].name == "Alice, Jr.");
    REQUIRE(parseResult.identities["102"].name == "Bob \"The Boss\"");
}

TEST_CASE("CSVParser::parse - empty lines skipped", "[csv]") {
    std::string csv = "\n101,Alice,Engineering\n\n102,Bob,Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 2);
}

TEST_CASE("CSVParser::parse - duplicate IDs tracked", "[csv]") {
    std::string csv = "101,Alice,Engineering\n101,Bob,Sales\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 1);
    // First occurrence wins; duplicates are counted and rejected at validation
    REQUIRE(parseResult.identities["101"].name == "Alice");
    REQUIRE(parseResult.totalRows == 2);
    REQUIRE(parseResult.validRows == 1);
    REQUIRE(parseResult.duplicateRows == 1);
}

TEST_CASE("CSVParser::parse - malformed rows tracked", "[csv]") {
    std::string csv = "101,Alice,Engineering\n102,Bob\n103,Charlie,Marketing,Extra\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 2); // 101 and 103 (first 3 cols)
    REQUIRE(parseResult.totalRows == 3);
    REQUIRE(parseResult.validRows == 2);
    REQUIRE(parseResult.malformedRows == 1);
    REQUIRE(parseResult.duplicateRows == 0);
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

TEST_CASE("CSVParser::parse - reordered header maps by name", "[csv]") {
    std::string csv = "department,name,id\nEngineering,Alice,101\nSales,Bob,102\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 2);
    REQUIRE(parseResult.identities["101"].name == "Alice");
    REQUIRE(parseResult.identities["101"].department == "Engineering");
    REQUIRE(parseResult.identities["102"].name == "Bob");
    REQUIRE(parseResult.identities["102"].department == "Sales");
    REQUIRE(parseResult.totalRows == 2);
    REQUIRE(parseResult.validRows == 2);
    REQUIRE(parseResult.malformedRows == 0);
}

TEST_CASE("CSVParser::parse - header missing required column fails", "[csv]") {
    std::string csv = "id,name\n101,Alice\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "VALIDATION_SCHEMA");
}

TEST_CASE("CSVParser::parse - case-insensitive header", "[csv]") {
    std::string csv = "ID,Name,Department\n101,Alice,Engineering\n";
    auto result = CSVParser::parse(csv);
    REQUIRE(result.hasValue());
    REQUIRE(result.value().identities.size() == 1);
    REQUIRE(result.value().identities["101"].name == "Alice");
}

TEST_CASE("CSVParser::parseFile - streams from disk", "[csv]") {
    auto path = std::filesystem::temp_directory_path() / "idsentinel_test_parse.csv";
    {
        std::ofstream f(path);
        f << "department,name,id\nEngineering,Alice,101\nSales,Bob,102\n";
    }
    auto result = CSVParser::parseFile(path);
    REQUIRE(result.hasValue());
    auto parseResult = result.value();
    REQUIRE(parseResult.identities.size() == 2);
    REQUIRE(parseResult.identities["101"].department == "Engineering");
    REQUIRE(parseResult.totalRows == 2);
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("CSVParser::parseFile - missing file returns error", "[csv]") {
    auto result = CSVParser::parseFile(std::filesystem::temp_directory_path() / "idsentinel_nope.csv");
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "FILE_OPEN");
}

TEST_CASE("CSVParser::loadFromFile - missing file returns error", "[csv]") {
    auto result = CSVParser::loadFromFile(std::filesystem::path("/nonexistent/path.csv"));
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "FILE_OPEN");
}