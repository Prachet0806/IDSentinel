#include <catch2/catch_test_macros.hpp>
#include <connectors/NetworkConnector.h>

// Process-scoped curl state for the test binary (mirrors main.cpp).
namespace {
CurlGlobal g_curlGlobal;
}

TEST_CASE("NetworkConnector - rejects plain HTTP", "[network]") {
    NetworkConnector net;
    auto result = net.fetch("http://example.com/hr_feed.csv");
    REQUIRE(result.hasError());
    REQUIRE(result.error().code == "URL_SCHEME");
}

TEST_CASE("NetworkConnector - rejects non-HTTP schemes", "[network]") {
    NetworkConnector net;
    REQUIRE(net.fetch("ftp://example.com/hr_feed.csv").error().code == "URL_SCHEME");
    REQUIRE(net.fetch("file:///etc/passwd").error().code == "URL_SCHEME");
    REQUIRE(net.fetch("not-a-url").error().code == "URL_SCHEME");
    REQUIRE(net.fetch("").error().code == "URL_SCHEME");
}

TEST_CASE("NetworkConnector - HTTPS passes scheme validation", "[network]") {
    NetworkConnector net;
    net.setTimeouts(2, 5);
    net.setMaxRetries(0);
    // .invalid never resolves (RFC 2606): fails fast on DNS, proving the
    // URL cleared scheme validation and reached the transport layer.
    auto result = net.fetch("https://nonexistent.invalid/hr_feed.csv");
    REQUIRE(result.hasError());
    REQUIRE(result.error().code != "URL_SCHEME");
}

TEST_CASE("redactUrlForLogging - strips credentials, query, fragment", "[network]") {
    REQUIRE(redactUrlForLogging("https://user:s3cret@hr.example.com/feed?token=abc#frag")
            == "https://[credentials]@hr.example.com/feed");
    REQUIRE(redactUrlForLogging("https://hr.example.com/feed?token=abc")
            == "https://hr.example.com/feed");
    REQUIRE(redactUrlForLogging("https://hr.example.com/feed")
            == "https://hr.example.com/feed");
    REQUIRE(redactUrlForLogging("https://hr.example.com:8443/feed")
            == "https://hr.example.com:8443/feed");
    REQUIRE(redactUrlForLogging("not-a-url") == "[redacted-url]");
    REQUIRE(redactUrlForLogging("") == "[redacted-url]");
}

TEST_CASE("NetworkConnector - uppercase HTTPS scheme accepted", "[network]") {
    NetworkConnector net;
    net.setTimeouts(2, 5);
    net.setMaxRetries(0);
    auto result = net.fetch("HTTPS://nonexistent.invalid/hr_feed.csv");
    REQUIRE(result.hasError());
    REQUIRE(result.error().code != "URL_SCHEME");
}
