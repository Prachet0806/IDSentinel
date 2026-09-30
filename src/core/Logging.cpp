#include "Logging.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/formatter.h>
#include <spdlog/details/log_msg.h>
#include <nlohmann/json.hpp>
#include <fmt/core.h>
#include <ctime>
#include <chrono>

namespace {
// Pattern-based JSON sinks break the moment a message contains a quote,
// backslash, or control character. This formatter serializes through a real
// JSON library so every field is escaped correctly.
class JsonFormatter final : public spdlog::formatter {
public:
    void format(const spdlog::details::log_msg& msg, spdlog::memory_buf_t& dest) override {
        nlohmann::json j;
        j["timestamp"] = formatTime(msg.time);
        auto levelSv = spdlog::level::to_string_view(msg.level);
        j["level"] = std::string(levelSv.data(), levelSv.size());
        j["logger"] = std::string(msg.logger_name.begin(), msg.logger_name.end());
        j["message"] = std::string(msg.payload.begin(), msg.payload.end());
        std::string out = j.dump();
        dest.append(out.data(), out.data() + out.size());
        dest.push_back('\n');
    }

    std::unique_ptr<spdlog::formatter> clone() const override {
        return std::make_unique<JsonFormatter>();
    }

private:
    static std::string formatTime(spdlog::log_clock::time_point tp) {
        std::time_t t = spdlog::log_clock::to_time_t(tp);
        std::tm localTm{};
        std::tm utcTm{};
#ifdef _WIN32
        localtime_s(&localTm, &t);
        gmtime_s(&utcTm, &t);
#else
        localtime_r(&t, &localTm);
        gmtime_r(&t, &utcTm);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &localTm);
        long ms = static_cast<long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                tp.time_since_epoch()).count() % 1000);
        // Portable UTC offset: how far local wall-clock is ahead of UTC.
        long offsetSec = static_cast<long>(std::difftime(std::mktime(&localTm), std::mktime(&utcTm)));
        char sign = offsetSec < 0 ? '-' : '+';
        long absOff = offsetSec < 0 ? -offsetSec : offsetSec;
        return fmt::format("{}.{:03}{}{:02}{:02}", buf, ms, sign, absOff / 3600, (absOff % 3600) / 60);
    }
};

spdlog::sink_ptr createConsoleSink(LogFormat format, LogLevel level) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(toSpdlogLevel(level));
    if (format == LogFormat::Json) {
        console_sink->set_formatter(std::make_unique<JsonFormatter>());
    } else {
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    }
    return console_sink;
}

spdlog::sink_ptr createFileSink(LogFormat format, LogLevel level,
                                const std::filesystem::path& filePath,
                                size_t maxFileSizeMb, size_t maxFiles, bool dailyRotation) {
    if (!filePath.parent_path().empty()) {
        std::filesystem::create_directories(filePath.parent_path());
    }

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
        file_sink->set_formatter(std::make_unique<JsonFormatter>());
    } else {
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    }
    return file_sink;
}
}

void initLogging(LogFormat format, LogLevel level, std::optional<std::filesystem::path> filePath,
                 size_t maxFileSizeMb, size_t maxFiles, bool dailyRotation) {
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(createConsoleSink(format, level));

    if (filePath && !filePath->empty()) {
        sinks.push_back(createFileSink(format, level, *filePath, maxFileSizeMb, maxFiles, dailyRotation));
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
