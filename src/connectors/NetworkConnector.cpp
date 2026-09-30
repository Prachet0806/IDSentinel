#include "NetworkConnector.h"
#include <spdlog/spdlog.h>
#include <cstring>
#include <cctype>
#include <thread>
#include <chrono>
#include <cstdlib>

std::string redactUrlForLogging(const std::string& url) {
    auto schemePos = url.find("://");
    if (schemePos == std::string::npos) return "[redacted-url]";
    std::string out = url.substr(0, schemePos + 3);
    std::string rest = url.substr(schemePos + 3);
    // Drop query string and fragment.
    rest = rest.substr(0, rest.find_first_of("?#"));
    // Drop userinfo credentials.
    auto atPos = rest.rfind('@');
    if (atPos != std::string::npos) {
        rest = "[credentials]@" + rest.substr(atPos + 1);
    }
    return out + rest;
}

namespace {
// Only set when explicitly opted in for local development. There is no
// config-file or CLI knob for this: disabling TLS verification must be a
// deliberate per-process environment decision, never a persisted setting.
bool devDisableTls() {
    const char* v = std::getenv("IDSENTINEL_DEV_DISABLE_TLS");
    return v != nullptr && (std::strcmp(v, "1") == 0);
}

bool transientHttp(long httpCode) {
    return httpCode == 408 || httpCode == 429 || (httpCode >= 500 && httpCode < 600);
}
}

CurlGlobal::CurlGlobal() {
    curl_global_init(CURL_GLOBAL_ALL);
}

CurlGlobal::~CurlGlobal() {
    curl_global_cleanup();
}

NetworkConnector::NetworkConnector() {
    curl_ = curl_easy_init();
}

NetworkConnector::~NetworkConnector() {
    if (curl_) curl_easy_cleanup(curl_);
}

void NetworkConnector::setTimeouts(long connectTimeoutSec, long totalTimeoutSec) {
    connectTimeoutSec_ = connectTimeoutSec;
    totalTimeoutSec_ = totalTimeoutSec;
}

void NetworkConnector::setCABundle(const std::string& caBundlePath) {
    caBundlePath_ = caBundlePath;
}

void NetworkConnector::setMaxResponseBytes(size_t maxBytes) {
    maxResponseBytes_ = maxBytes;
}

void NetworkConnector::setMaxRetries(int maxRetries) {
    maxRetries_ = maxRetries < 0 ? 0 : maxRetries;
}

size_t NetworkConnector::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    WriteState* state = static_cast<WriteState*>(userp);
    if (state->buffer->size() + total > state->maxBytes) {
        state->limitExceeded = true;
        return 0; // Abort the transfer; curl reports CURLE_WRITE_ERROR.
    }
    state->buffer->append(static_cast<char*>(contents), total);
    return total;
}

bool NetworkConnector::isHttpsUrl(const std::string& url) {
    auto pos = url.find("://");
    if (pos == std::string::npos) return false;
    std::string scheme = url.substr(0, pos);
    for (char& c : scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return scheme == "https";
}

bool NetworkConnector::isTransient(CURLcode code, long httpCode) {
    if (code == CURLE_COULDNT_CONNECT || code == CURLE_COULDNT_RESOLVE_HOST ||
        code == CURLE_OPERATION_TIMEDOUT || code == CURLE_RECV_ERROR ||
        code == CURLE_SEND_ERROR || code == CURLE_GOT_NOTHING ||
        code == CURLE_PARTIAL_FILE) {
        return true;
    }
    return transientHttp(httpCode);
}

Result<std::string> NetworkConnector::performOnce(const std::string& url) {
    if (!curl_) return Result<std::string>::err(Error{ "CURL_INIT", "Failed to initialize CURL handle" });

    std::string response;
    WriteState state{ &response, maxResponseBytes_, false };
    curl_easy_reset(curl_);

    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &state);

    curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, connectTimeoutSec_);
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, totalTimeoutSec_);

    if (!caBundlePath_.empty()) {
        curl_easy_setopt(curl_, CURLOPT_CAINFO, caBundlePath_.c_str());
    }

    if (devDisableTls()) {
        SPDLOG_CRITICAL("IDSENTINEL_DEV_DISABLE_TLS=1: TLS verification DISABLED for {} (dev only, never in production)", redactUrlForLogging(url));
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 2L);
    }

    curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_, CURLOPT_MAXREDIRS, 5L);
    // Redirects must never downgrade to plaintext or exotic protocols.
    curl_easy_setopt(curl_, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl_, CURLOPT_USERAGENT, "IDSentinel/1.0");

    CURLcode res = curl_easy_perform(curl_);
    if (state.limitExceeded) {
        SPDLOG_ERROR("Response from {} exceeded size limit ({} bytes)", redactUrlForLogging(url), maxResponseBytes_);
        return Result<std::string>::err(Error{ "RESPONSE_TOO_LARGE",
            "Response exceeded size limit of " + std::to_string(maxResponseBytes_) + " bytes" });
    }
    if (res != CURLE_OK) {
        std::string err = curl_easy_strerror(res);
        SPDLOG_ERROR("Network fetch failed for {}: {}", redactUrlForLogging(url), err);
        long httpCode = 0;
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
        if (isTransient(res, httpCode)) {
            return Result<std::string>::err(Error{ "CURL_TRANSIENT", err });
        }
        return Result<std::string>::err(Error{ "CURL_ERROR", err });
    }

    long httpCode = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode < 200 || httpCode >= 300) {
        SPDLOG_ERROR("HTTP error {} for {}", httpCode, redactUrlForLogging(url));
        if (transientHttp(httpCode)) {
            return Result<std::string>::err(Error{ "HTTP_TRANSIENT", "HTTP " + std::to_string(httpCode) });
        }
        return Result<std::string>::err(Error{ "HTTP_ERROR", "HTTP " + std::to_string(httpCode) });
    }

    SPDLOG_DEBUG("Fetched {} bytes from {}", response.size(), redactUrlForLogging(url));
    return Result<std::string>::ok(std::move(response));
}

Result<std::string> NetworkConnector::fetch(const std::string& url) {
    // Fail closed: the HR feed is fetched over the network, so only
    // encrypted HTTPS transport is acceptable.
    if (!isHttpsUrl(url)) {
        SPDLOG_ERROR("Refusing to fetch non-HTTPS URL: {}", redactUrlForLogging(url));
        return Result<std::string>::err(Error{ "URL_SCHEME", "Only HTTPS URLs are allowed" });
    }

    Result<std::string> last = Result<std::string>::err(Error{ "CURL_ERROR", "No attempts made" });
    for (int attempt = 0; attempt <= maxRetries_; ++attempt) {
        if (attempt > 0) {
            // Exponential backoff: 1s, 2s, 4s, ...
            auto delay = std::chrono::seconds(1 << (attempt - 1));
            SPDLOG_WARN("Retrying fetch of {} (attempt {}/{}) after {}s",
                        redactUrlForLogging(url), attempt + 1, maxRetries_ + 1, delay.count());
            std::this_thread::sleep_for(delay);
        }
        last = performOnce(url);
        if (last.hasValue()) return last;
        const std::string& code = last.error().code;
        if (code != "CURL_TRANSIENT" && code != "HTTP_TRANSIENT") {
            return last; // Permanent failure: do not retry.
        }
        SPDLOG_WARN("Transient failure fetching {}: {}", redactUrlForLogging(url), last.error().message);
    }
    return last;
}
