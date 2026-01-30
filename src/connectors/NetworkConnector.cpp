#include "NetworkConnector.h"
#include <iostream>

NetworkConnector::NetworkConnector() {
    curl_global_init(CURL_GLOBAL_ALL);
}

NetworkConnector::~NetworkConnector() {
    curl_global_cleanup();
}

size_t NetworkConnector::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    std::string* buffer = static_cast<std::string*>(userp);
    buffer->append(static_cast<char*>(contents), total);
    return total;
}

bool NetworkConnector::fetch(const std::string& url, std::string& response) {
    response.clear();
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // Enterprise resilience
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "[NETWORK ERROR] " << curl_easy_strerror(res) << "\n";
        curl_easy_cleanup(curl);
        return false;
    }

    curl_easy_cleanup(curl);
    return true;
}
