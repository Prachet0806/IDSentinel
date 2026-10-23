#pragma once
#include <string>
#include <string_view>
#include <cstdint>

enum class ViolationType : std::uint8_t {
    OrphanAccount,
    MissingAccount,
    AttributeDrift
};

enum class Severity : std::uint8_t {
    Critical,
    High,
    Medium,
    Low
};

enum class RunStatus : std::uint8_t {
    Running,
    Success,
    Failed,
    Abandoned
};

enum class FindingStatus : std::uint8_t {
    Open,
    Review,
    Remediated
};

[[nodiscard]] std::string_view toString(ViolationType v) noexcept;
[[nodiscard]] std::string_view toString(Severity s) noexcept;
[[nodiscard]] std::string_view toString(RunStatus rs) noexcept;
[[nodiscard]] std::string_view toString(FindingStatus fs) noexcept;

[[nodiscard]] ViolationType violationTypeFromString(std::string_view s);
[[nodiscard]] Severity severityFromString(std::string_view s);
[[nodiscard]] RunStatus runStatusFromString(std::string_view s);
[[nodiscard]] FindingStatus findingStatusFromString(std::string_view s);
