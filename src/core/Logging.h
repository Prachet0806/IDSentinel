#pragma once
#include <cstdint>
#include <string>
#include <optional>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

enum class LogFormat : std::uint8_t { Json, Text };
enum class LogLevel : std::uint8_t { Trace, Debug, Info, Warn, Error, Critical };

inline constexpr size_t kDefaultLogFiles = 30;
void initLogging(LogFormat format, LogLevel level, std::optional<std::filesystem::path> filePath,
                 size_t maxFileSizeMb = 10, size_t maxFiles = kDefaultLogFiles, bool dailyRotation = false);

spdlog::level::level_enum toSpdlogLevel(LogLevel level);
