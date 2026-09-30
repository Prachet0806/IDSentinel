#include "CSVParser.h"
#include <sstream>
#include <fstream>
#include <vector>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <spdlog/spdlog.h>

namespace {
std::string trimAndLower(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n'))
        ++start;
    s = s.substr(start);
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
}

bool CSVParser::isHeaderLine(const std::string& line) {
    return trimAndLower(line) == "id,name,department";
}

std::vector<std::string> CSVParser::parseRow(const std::string& line) {
    std::vector<std::string> cols;
    std::string current;
    bool inQuotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') {
            if (inQuotes && i + 1 < line.size() && line[i + 1] == '"') {
                current.push_back('"');
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (c == ',' && !inQuotes) {
            cols.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    cols.push_back(current);
    for (auto& col : cols) {
        if (!col.empty() && col.back() == '\r') col.pop_back();
    }
    return cols;
}

namespace {
// Column positions resolved either positionally (no header row) or by
// header name (order-independent). -1 = unresolved (positional fallback).
struct ColumnMap {
    int id = 0;
    int name = 1;
    int department = 2;
    bool fromHeader = false;
};

bool hasIdField(const std::vector<std::string>& cols) {
    for (const auto& c : cols) {
        if (trimAndLower(c) == "id") return true;
    }
    return false;
}

// Fail-closed schema check (I1): a header row must name every required
// column, otherwise the source's layout is unknown and parsing stops.
Result<ColumnMap> mapHeaderColumns(const std::vector<std::string>& header) {
    ColumnMap map;
    map.id = map.name = map.department = -1;
    for (size_t i = 0; i < header.size(); ++i) {
        std::string h = trimAndLower(header[i]);
        if (h == "id" && map.id < 0) map.id = static_cast<int>(i);
        else if (h == "name" && map.name < 0) map.name = static_cast<int>(i);
        else if (h == "department" && map.department < 0) map.department = static_cast<int>(i);
    }
    std::string missing;
    if (map.id < 0) missing += "id ";
    if (map.name < 0) missing += "name ";
    if (map.department < 0) missing += "department ";
    if (!missing.empty()) {
        return Result<ColumnMap>::err(Error{ "VALIDATION_SCHEMA",
            "CSV header is missing required column(s): " + missing });
    }
    map.fromHeader = true;
    return Result<ColumnMap>::ok(map);
}
}

Result<CSVParseResult> CSVParser::parseFromStream(std::istream& input) {
    CSVParseResult result;
    std::string line;
    bool firstNonEmpty = true;
    ColumnMap columns;

    while (std::getline(input, line)) {
        if (line.empty()) continue;

        std::vector<std::string> cols = parseRow(line);

        if (firstNonEmpty) {
            firstNonEmpty = false;
            if (isHeaderLine(line)) {
                continue; // Legacy exact header: positional layout assumed.
            }
            if (hasIdField(cols)) {
                // Header row with (possibly reordered) column names.
                auto mapResult = mapHeaderColumns(cols);
                if (mapResult.hasError()) {
                    return Result<CSVParseResult>::err(mapResult.error());
                }
                columns = mapResult.value();
                continue;
            }
        }
        ++result.totalRows;

        int need = std::max({columns.id, columns.name, columns.department});
        if (static_cast<int>(cols.size()) > need) {
            if (cols[columns.id].empty()) {
                SPDLOG_WARN("Row has empty id: {}", line);
                ++result.malformedRows;
            } else {
                auto [it, inserted] = result.identities.try_emplace(
                    cols[columns.id],
                    Identity{cols[columns.id], cols[columns.name], cols[columns.department]});
                if (!inserted) {
                    SPDLOG_WARN("Duplicate ID in CSV: {}, keeping first occurrence", cols[columns.id]);
                    ++result.duplicateRows;
                } else {
                    ++result.validRows;
                }
            }
        } else {
            bool anyContent = false;
            for (const auto& c : cols) {
                if (!c.empty()) { anyContent = true; break; }
            }
            if (anyContent) {
                SPDLOG_WARN("Row has insufficient columns (got {}, need {}): {}", cols.size(), need + 1, line);
            }
            ++result.malformedRows;
        }
    }
    return Result<CSVParseResult>::ok(std::move(result));
}

Result<CSVParseResult> CSVParser::parse(const std::string& csv) {
    std::stringstream ss(csv);
    return parseFromStream(ss);
}

Result<CSVParseResult> CSVParser::parseFile(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return Result<CSVParseResult>::err(Error{ "FILE_OPEN", "Unable to open file: " + path.string() });
    }
    auto result = parseFromStream(file);
    if (file.bad()) {
        return Result<CSVParseResult>::err(Error{ "FILE_READ", "Failed to read file: " + path.string() });
    }
    return result;
}

Result<void> CSVParser::parseStream(std::istream& input, RowCallback callback) {
    std::string line;
    bool firstNonEmpty = true;
    size_t lineNum = 0;

    while (std::getline(input, line)) {
        ++lineNum;
        if (line.empty()) continue;

        if (firstNonEmpty && isHeaderLine(line)) {
            firstNonEmpty = false;
            continue;
        }
        firstNonEmpty = false;

        std::vector<std::string> cols = parseRow(line);
        if (cols.size() >= 3 && !cols[0].empty()) {
            callback(cols);
        } else if (cols.size() > 0 && !cols[0].empty()) {
            SPDLOG_WARN("Line {}: insufficient columns (got {}, need 3)", lineNum, cols.size());
        }
    }
    return Result<void>::ok();
}

Result<std::string> CSVParser::loadFromFile(const std::string& path) {
    return loadFromFile(std::filesystem::path(path));
}

Result<std::string> CSVParser::loadFromFile(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return Result<std::string>::err(Error{ "FILE_OPEN", "Unable to open file: " + path.string() });
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    if (!file) {
        return Result<std::string>::err(Error{ "FILE_READ", "Failed to read file: " + path.string() });
    }
    return Result<std::string>::ok(buffer.str());
}