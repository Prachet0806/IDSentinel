#include "Policy.h"
#include <array>
#include <stdexcept>

std::string_view toString(ViolationType v) noexcept {
    switch (v) {
        case ViolationType::OrphanAccount: return "ORPHAN_ACCOUNT";
        case ViolationType::MissingAccount: return "MISSING_ACCOUNT";
        case ViolationType::AttributeDrift: return "ATTRIBUTE_DRIFT";
    }
    return "UNKNOWN";
}

std::string_view toString(Severity s) noexcept {
    switch (s) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
    }
    return "UNKNOWN";
}

std::string_view toString(RunStatus rs) noexcept {
    switch (rs) {
        case RunStatus::Running: return "RUNNING";
        case RunStatus::Success: return "SUCCESS";
        case RunStatus::Failed: return "FAILED";
        case RunStatus::Abandoned: return "ABANDONED";
    }
    return "UNKNOWN";
}

std::string_view toString(FindingStatus fs) noexcept {
    switch (fs) {
        case FindingStatus::Open: return "OPEN";
        case FindingStatus::Review: return "REVIEW";
        case FindingStatus::Remediated: return "REMEDIATED";
    }
    return "UNKNOWN";
}

ViolationType violationTypeFromString(std::string_view s) {
    if (s == "ORPHAN_ACCOUNT") return ViolationType::OrphanAccount;
    if (s == "MISSING_ACCOUNT") return ViolationType::MissingAccount;
    if (s == "ATTRIBUTE_DRIFT") return ViolationType::AttributeDrift;
    throw std::invalid_argument("Unknown violation type: " + std::string(s));
}

Severity severityFromString(std::string_view s) {
    if (s == "CRITICAL") return Severity::Critical;
    if (s == "HIGH") return Severity::High;
    if (s == "MEDIUM") return Severity::Medium;
    if (s == "LOW") return Severity::Low;
    throw std::invalid_argument("Unknown severity: " + std::string(s));
}

RunStatus runStatusFromString(std::string_view s) {
    if (s == "RUNNING") return RunStatus::Running;
    if (s == "SUCCESS") return RunStatus::Success;
    if (s == "FAILED") return RunStatus::Failed;
    if (s == "ABANDONED") return RunStatus::Abandoned;
    throw std::invalid_argument("Unknown run status: " + std::string(s));
}

FindingStatus findingStatusFromString(std::string_view s) {
    if (s == "OPEN") return FindingStatus::Open;
    if (s == "REVIEW") return FindingStatus::Review;
    if (s == "REMEDIATED") return FindingStatus::Remediated;
    throw std::invalid_argument("Unknown finding status: " + std::string(s));
}