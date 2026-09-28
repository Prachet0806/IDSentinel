#pragma once
#include <string>
#include <optional>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

enum class LogFormat { Json, Text };
enum class LogLevel { Trace, Debug, Info, Warn, Error, Critical };

void initLogging(LogFormat format, LogLevel level, std::optional<std::filesystem::path> filePath,
                 size_t maxFileSizeMb = 10, size_t maxFiles = 30, bool dailyRotation = true);

spdlog::level::level_enum toSpdlogLevel(LogLevel level);