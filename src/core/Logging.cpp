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
std::string formatTime(spdlog::log_clock::time_point tp) { // NOLINT(readability-function-cognitive-complexity): platform branches are each trivial; splitting hurts readability
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

    // Calculate UTC offset correctly, handling DST.
    long offsetSec = 0;
#ifdef _WIN32
    // Interpret the broken-down local time as UTC; the epoch difference is
    // the offset that was in effect for this timestamp, including DST.
    std::tm localAsUtc = localTm;
    offsetSec = static_cast<long>(std::difftime(_mkgmtime(&localAsUtc), t));
#else
    // On POSIX, use tm_gmtoff if available (GNU extension)
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    offsetSec = localTm.tm_gmtoff;
#else
    // Fallback: compute using mktime/gmtime (may have DST issues at boundaries)
    // NOLINTNEXTLINE(bugprone-suspicious-stringview-obj-cpy, bugprone-misplaced-widening-cast): mktime intentionally normalizes a copy of broken-down time
    offsetSec = static_cast<long>(std::difftime(std::mktime(&localTm), std::mktime(&utcTm)));
#endif
#endif

    char sign = offsetSec < 0 ? '-' : '+';
    long absOff = offsetSec < 0 ? -offsetSec : offsetSec;
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &localTm);
    constexpr long kMillisPerSec = 1000;
    constexpr long kSecsPerHour = 3600;
    constexpr long kSecsPerMin = 60;
    long ms = static_cast<long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            tp.time_since_epoch()).count() % kMillisPerSec);
    return fmt::format("{}.{:03}{}{:02}{:02}", buf, ms, sign < 0 ? '-' : '+', absOff / kSecsPerHour, (absOff % kSecsPerHour) / kSecsPerMin);
}

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
        std::string out = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        dest.append(out.data(), out.data() + out.size());
        dest.push_back('\n');
    }

    std::unique_ptr<spdlog::formatter> clone() const override {
        return std::make_unique<JsonFormatter>();
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
            filePath.string(), 0, 0, false, static_cast<std::uint16_t>(maxFiles));
    } else {
        file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            filePath.string(), maxFileSizeMb * 1024 * 1024, maxFiles, true); // NOLINT(readability-magic-numbers): MiB to bytes
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
