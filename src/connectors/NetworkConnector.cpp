#include "NetworkConnector.h"
#include <spdlog/spdlog.h>
#include <cstring>

NetworkConnector::NetworkConnector() {
    curl_global_init(CURL_GLOBAL_ALL);
    curl_ = curl_easy_init();
}

NetworkConnector::~NetworkConnector() {
    if (curl_) curl_easy_cleanup(curl_);
    curl_global_cleanup();
}

void NetworkConnector::setTimeouts(long connectTimeoutSec, long totalTimeoutSec) {
    connectTimeoutSec_ = connectTimeoutSec;
    totalTimeoutSec_ = totalTimeoutSec;
}

void NetworkConnector::setCABundle(const std::string& caBundlePath) {
    caBundlePath_ = caBundlePath;
}

void NetworkConnector::disableTLSVerification(bool disable) {
    disableTLS_ = disable;
}

size_t NetworkConnector::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    std::string* buffer = static_cast<std::string*>(userp);
    buffer->append(static_cast<char*>(contents), total);
    return total;
}

Result<std::string> NetworkConnector::fetch(const std::string& url) {
    if (!curl_) return Result<std::string>::err(Error{ "CURL_INIT", "Failed to initialize CURL handle" });

    std::string response;
    curl_easy_reset(curl_);

    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, connectTimeoutSec_);
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, totalTimeoutSec_);

    if (!caBundlePath_.empty()) {
        curl_easy_setopt(curl_, CURLOPT_CAINFO, caBundlePath_.c_str());
    }

    if (disableTLS_) {
        SPDLOG_WARN("TLS verification disabled for {}", url);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 2L);
    }

    curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl_, CURLOPT_USERAGENT, "IDSentinel/1.0");

    CURLcode res = curl_easy_perform(curl_);
    if (res != CURLE_OK) {
        std::string err = curl_easy_strerror(res);
        SPDLOG_ERROR("Network fetch failed for {}: {}", url, err);
        return Result<std::string>::err(Error{ "CURL_ERROR", err });
    }

    long httpCode = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode < 200 || httpCode >= 300) {
        SPDLOG_ERROR("HTTP error {} for {}", httpCode, url);
        return Result<std::string>::err(Error{ "HTTP_ERROR", "HTTP " + std::to_string(httpCode) });
    }

    SPDLOG_DEBUG("Fetched {} bytes from {}", response.size(), url);
    return Result<std::string>::ok(std::move(response));
}