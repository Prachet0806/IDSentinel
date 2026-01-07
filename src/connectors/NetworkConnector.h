#pragma once
#include <string>
#include <curl/curl.h>

class NetworkConnector {
public:
    NetworkConnector();
    ~NetworkConnector();

    bool fetch(const std::string& url, std::string& response);

private:
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
};
