#include "CSVParser.h"
#include <sstream>
#include <fstream>
#include <vector>
#include <iostream>

namespace {
std::vector<std::string> parseRow(const std::string& line) {
    std::vector<std::string> cols;
    std::string current;
    bool inQuotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"' ) {
            // double quote inside quoted section -> escape
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
    // trim trailing CR for Windows endings
    for (auto& col : cols) {
        if (!col.empty() && col.back() == '\r') {
            col.pop_back();
        }
    }
    return cols;
}
}

std::unordered_map<std::string, Identity> CSVParser::parse(const std::string& csv) {
    std::unordered_map<std::string, Identity> identities;
    std::stringstream ss(csv);
    std::string line;

    while (std::getline(ss, line)) {
        if (line.empty()) continue;

        std::vector<std::string> cols = parseRow(line);

        // Expected: ID, Name, Dept
        if (cols.size() >= 3 && !cols[0].empty()) {
            identities[cols[0]] = {cols[0], cols[1], cols[2]};
        }
    }
    return identities;
}

std::string CSVParser::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Unable to open file: " << path << "\n";
        return {};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}
