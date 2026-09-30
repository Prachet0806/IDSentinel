#include <catch2/catch_test_macros.hpp>
#include <core/ProcessLock.h>
#include <filesystem>

TEST_CASE("ProcessLock - acquire, contend, release", "[lock]") {
    auto lockPath = std::filesystem::temp_directory_path() / "idsentinel_test.lock";
    std::error_code ec;
    std::filesystem::remove(lockPath, ec);

    ProcessLock first(lockPath);
    auto r1 = first.tryAcquire();
    REQUIRE(r1.hasValue());
    REQUIRE(r1.value() == true);
    REQUIRE(first.held() == true);

    // Second guard on the same path must fail fast while the first is held.
    ProcessLock second(lockPath);
    auto r2 = second.tryAcquire();
    REQUIRE(r2.hasValue());
    REQUIRE(r2.value() == false);
    REQUIRE(second.held() == false);

    std::filesystem::remove(lockPath, ec);
}

TEST_CASE("ProcessLock - released on destruction", "[lock]") {
    auto lockPath = std::filesystem::temp_directory_path() / "idsentinel_test2.lock";
    std::error_code ec;
    std::filesystem::remove(lockPath, ec);

    {
        ProcessLock first(lockPath);
        REQUIRE(first.tryAcquire().value() == true);
    } // destructor releases

    ProcessLock second(lockPath);
    auto r = second.tryAcquire();
    REQUIRE(r.hasValue());
    REQUIRE(r.value() == true);

    std::filesystem::remove(lockPath, ec);
}
