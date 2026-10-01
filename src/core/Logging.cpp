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
std::string formatTime(spdlog::log_clock::time_point tp) {
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
    // On Windows, use _get_timezone and _get_dstbias
    long timezone = 0;
    _get_timezone(&timezone);
    long dstbias = 0;
    _get_dstbias(&dstbias);
    offsetSec = -timezone - dstbias;
    // Check if DST is in effect for this time
    if (localTm.tm_isdst > 0) {
        offsetSec -= 3600; // DST adds an hour
    }
#else
    // On POSIX, use tm_gmtoff if available (GNU extension)
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    offsetSec = localTm.tm_gmtoff;
#else
    // Fallback: compute using mktime/gmtime (may have DST issues at boundaries)
    offsetSec = static_cast<long>(std::difftime(std::mktime(&localTm), std::mktime(&utcTm)));
#endif
#endif
    
    char sign = offsetSec < 0 ? '-' : '+';
    long absOff = offsetSec < 0 ? -offsetSec : offsetSec;
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &localTm);
    long ms = static_cast<long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            tp.time_since_epoch()).count() % 1000);
    return fmt::format("{}.{:03}{}{:02}{:02}", buf, ms, sign < 0 ? '-' : '+', absOff / 3600, (absOff % 3600) / 60);
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
        // Handle potential non-UTF-8 in message payload
        std::string message;
        try {
            message = std::string(msg.payload.begin(), msg.payload.end());
            // Validate UTF-8 by attempting to parse as JSON
            nlohmann::json::parse("\"" + message + "\"");
        } catch (...) {
            // Replace invalid UTF-8 sequences with replacement character
            message = sanitizeUtf8(std::string(msg.payload.begin(), msg.payload.end()));
        }
        j["message"] = message;
        std::string out = j.dump();
        dest.append(out.data(), out.data() + out.size());
        dest.push_back('\n');
    }

    std::unique_ptr<spdlog::formatter> clone() const override {
        return std::make_unique<JsonFormatter>();
    }

private:
    static std::string sanitizeUtf8(std::string input) {
        std::string output;
        output.reserve(input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(input[i]);
            if (c < 0x80) {
                // ASCII - copy as-is
                output.push_back(input[i]);
            } else if ((c & 0xE0) == 0xC0) {
                // 2-byte sequence
                if (i + 1 < input.size() && (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80) {
                    output.push_back(input[i]);
                    output.push_back(input[i + 1]);
                    ++i;
                } else {
                    output.push_back('\xEF');
                    output.push_back('\xBF');
                    output.push_back('\xBD'); // Replacement character
                }
            } else if ((c & 0xF0) == 0xE0) {
                // 3-byte sequence
                if (i + 2 < input.size() &&
                    (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80 &&
                    (static_cast<unsigned char>(input[i + 2]) & 0xC0) == 0x80) {
                    output.push_back(input[i]);
                    output.push_back(input[i + 1]);
                    output.push_back(input[i + 2]);
                    i += 2;
                } else {
                    output.push_back('\xEF');
                    output.push_back('\xBF');
                    output.push_back('\xBD');
                }
            } else if ((c & 0xF8) == 0xF0) {
                // 4-byte sequence
                if (i + 3 < input.size() &&
                    (static_cast<unsigned char>(input[i + 1]) & 0xC0) == 0x80 &&
                    (static_cast<unsigned char>(input[i + 2]) & 0xC0) == 0x80 &&
                    (static_cast<unsigned char>(input[i + 3]) & 0xC0) == 0x80) {
                    output.push_back(input[i]);
                    output.push_back(input[i + 1]);
                    output.push_back(input[i + 2]);
                    output.push_back(input[i + 3]);
                    i += 3;
                } else {
                    output.push_back('\xEF');
                    output.push_back('\xBF');
                    output.push_back('\xBD');
                }
            } else {
                // Invalid leading byte
                output.push_back('\xEF');
                output.push_back('\xBF');
                output.push_back('\xBD');
            }
        }
        return output;
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