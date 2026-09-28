#pragma once
#include <string>
#include <curl/curl.h>
#include "core/Result.h"

class NetworkConnector {
public:
    NetworkConnector();
    ~NetworkConnector();

    void setTimeouts(long connectTimeoutSec, long totalTimeoutSec);
    void setCABundle(const std::string& caBundlePath);
    void disableTLSVerification(bool disable);

    Result<std::string> fetch(const std::string& url);

private:
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);

    CURL* curl_{nullptr};
    long connectTimeoutSec_{5};
    long totalTimeoutSec_{10};
    std::string caBundlePath_;
    bool disableTLS_{false};
};