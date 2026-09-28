#include "CSVParser.h"
#include <sstream>
#include <fstream>
#include <vector>
#include <cctype>
#include <algorithm>
#include <filesystem>

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

bool isHeaderLine(const std::string& line) {
    return trimAndLower(line) == "id,name,department";
}

std::vector<std::string> parseRow(const std::string& line) {
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
}

Result<std::unordered_map<std::string, Identity>> CSVParser::parse(const std::string& csv) {
    std::unordered_map<std::string, Identity> identities;
    std::stringstream ss(csv);
    std::string line;
    bool firstNonEmpty = true;

    while (std::getline(ss, line)) {
        if (line.empty()) continue;

        if (firstNonEmpty && isHeaderLine(line)) {
            firstNonEmpty = false;
            continue;
        }
        firstNonEmpty = false;

        std::vector<std::string> cols = parseRow(line);

        if (cols.size() >= 3 && !cols[0].empty()) {
            auto [it, inserted] = identities.try_emplace(cols[0], Identity{cols[0], cols[1], cols[2]});
            if (!inserted) {
                SPDLOG_WARN("Duplicate ID in CSV: {}, overwriting", cols[0]);
            }
        } else if (cols.size() > 0 && !cols[0].empty()) {
            SPDLOG_WARN("Row has insufficient columns (got {}, need 3): {}", cols.size(), line);
        }
    }
    return Result<std::unordered_map<std::string, Identity>>::ok(std::move(identities));
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