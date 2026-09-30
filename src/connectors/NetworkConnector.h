#pragma once
#include <string>
#include <curl/curl.h>
#include "core/Result.h"

// Logging-safe URL: strips userinfo credentials, query strings, and
// fragments so secrets and tokens never land in log files.
std::string redactUrlForLogging(const std::string& url);

// Process-scoped libcurl global state. Instantiate once in main() —
// curl_global_init/cleanup must bracket the whole process lifetime, not
// individual connectors (cleanup while other handles exist is undefined).
class CurlGlobal {
public:
    CurlGlobal();
    ~CurlGlobal();
    CurlGlobal(const CurlGlobal&) = delete;
    CurlGlobal& operator=(const CurlGlobal&) = delete;
};

class NetworkConnector {
public:
    NetworkConnector();
    ~NetworkConnector();

    NetworkConnector(const NetworkConnector&) = delete;
    NetworkConnector& operator=(const NetworkConnector&) = delete;

    void setTimeouts(long connectTimeoutSec, long totalTimeoutSec);
    void setCABundle(const std::string& caBundlePath);
    void setMaxResponseBytes(size_t maxBytes);
    void setMaxRetries(int maxRetries);

    Result<std::string> fetch(const std::string& url);

private:
    struct WriteState {
        std::string* buffer;
        size_t maxBytes;
        bool limitExceeded = false;
    };
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
    static bool isHttpsUrl(const std::string& url);
    static bool isTransient(CURLcode code, long httpCode);

    Result<std::string> performOnce(const std::string& url);

    CURL* curl_{nullptr};
    long connectTimeoutSec_{5};
    long totalTimeoutSec_{10};
    std::string caBundlePath_;
    size_t maxResponseBytes_{10 * 1024 * 1024};
    int maxRetries_{3};
};
