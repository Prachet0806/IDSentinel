#pragma once
#include "../core/Identity.h"
#include "../core/Result.h"
#include <unordered_map>
#include <string>
#include <functional>
#include <istream>
#include <filesystem>

struct CSVParseResult {
    std::unordered_map<std::string, Identity> identities;
    size_t totalRows = 0;
    size_t validRows = 0;
    size_t malformedRows = 0;
    size_t duplicateRows = 0;
    // Quarantined malformed rows for inspection
    struct QuarantinedRow {
        size_t rowNumber;
        std::string rawLine;
        std::string reason;
    };
    std::vector<QuarantinedRow> quarantinedRows;
};

class CSVParser {
public:
    using RowCallback = std::function<void(const std::vector<std::string>&)>;

    static Result<CSVParseResult> parse(const std::string& csv);
    static Result<void> parseStream(std::istream& input, RowCallback callback);
    // Streams straight from disk: peaks at the identity map only, never
    // holding both the raw file contents and the map in memory at once.
    static Result<CSVParseResult> parseFile(const std::filesystem::path& path);
    static Result<std::string> loadFromFile(const std::string& path);
    static Result<std::string> loadFromFile(const std::filesystem::path& path);

private:
    static bool isHeaderLine(const std::string& line);
    static std::vector<std::string> parseRow(const std::string& line);
    static Result<CSVParseResult> parseFromStream(std::istream& input);
};