#pragma once
#include "../core/Identity.h"
#include "../core/Result.h"
#include <unordered_map>
#include <string>
#include <functional>
#include <istream>
#include <filesystem>

class CSVParser {
public:
    using RowCallback = std::function<void(const std::vector<std::string>&)>;

    static Result<std::unordered_map<std::string, Identity>> parse(const std::string& csv);
    static Result<void> parseStream(std::istream& input, RowCallback callback);
    static Result<std::string> loadFromFile(const std::string& path);
    static Result<std::string> loadFromFile(const std::filesystem::path& path);

private:
    static bool isHeaderLine(const std::string& line);
    static std::vector<std::string> parseRow(const std::string& line);
};