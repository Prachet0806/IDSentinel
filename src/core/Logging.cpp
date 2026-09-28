#include "Logging.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/ostr.h>
#include <iostream>

namespace {
std::shared_ptr<spdlog::logger> createConsoleLogger(LogFormat format, LogLevel level) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(toSpdlogLevel(level));
    if (format == LogFormat::Json) {
        console_sink->set_pattern("%v");
        console_sink->set_formatter(std::make_unique<spdlog::pattern_formatter>(
            fmt::format("{{"
                "\"timestamp\":\"%Y-%m-%dT%H:%M:%S.%e%z\","
                "\"level\":\"%l\","
                "\"logger\":\"%n\","
                "\"message\":\"%v\""
            "}}"),
            spdlog::pattern_time_type::local
        ));
    } else {
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    }
    return console_sink;
}

std::shared_ptr<spdlog::logger> createFileLogger(LogFormat format, LogLevel level,
                                                 const std::filesystem::path& filePath,
                                                 size_t maxFileSizeMb, size_t maxFiles, bool dailyRotation) {
    std::filesystem::create_directories(filePath.parent_path());

    std::shared_ptr<spdlog::sinks::sink> file_sink;
    if (dailyRotation) {
        file_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>(
            filePath.string(), 0, 0, true, maxFiles);
    } else {
        file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            filePath.string(), maxFileSizeMb * 1024 * 1024, maxFiles, true);
    }
    file_sink->set_level(toSpdlogLevel(level));
    if (format == LogFormat::Json) {
        file_sink->set_pattern("%v");
        file_sink->set_formatter(std::make_unique<spdlog::pattern_formatter>(
            fmt::format("{{"
                "\"timestamp\":\"%Y-%m-%dT%H:%M:%S.%e%z\","
                "\"level\":\"%l\","
                "\"logger\":\"%n\","
                "\"message\":\"%v\""
            "}}"),
            spdlog::pattern_time_type::local
        ));
    } else {
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    }
    return file_sink;
}
}

void initLogging(LogFormat format, LogLevel level, std::optional<std::filesystem::path> filePath,
                 size_t maxFileSizeMb, size_t maxFiles, bool dailyRotation) {
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(createConsoleLogger(format, level));

    if (filePath) {
        sinks.push_back(createFileLogger(format, level, *filePath, maxFileSizeMb, maxFiles, dailyRotation));
    }

    auto logger = std::make_shared<spdlog::logger>("idsentinel", sinks.begin(), sinks.end());
    logger->set_level(toSpdlogLevel(level));
    logger->flush_on(spdlog::level::warn);
    spdlog::set_default_logger(logger);
    spdlog::set_level(toSpdlogLevel(level));
}

spdlog::level::level_enum toSpdlogLevel(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return spdlog::level::trace;
        case LogLevel::Debug: return spdlog::level::debug;
        case LogLevel::Info: return spdlog::level::info;
        case LogLevel::Warn: return spdlog::level::warn;
        case LogLevel::Error: return spdlog::level::err;
        case LogLevel::Critical: return spdlog::level::critical;
    }
    return spdlog::level::info;
}