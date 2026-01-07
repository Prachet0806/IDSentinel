#pragma once
#include "../core/Identity.h"
#include <unordered_map>
#include <string>

class CSVParser {
public:
    static std::unordered_map<std::string, Identity> parse(const std::string& csv);
    static std::string loadFromFile(const std::string& path);
};
