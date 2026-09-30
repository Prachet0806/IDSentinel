cmake_minimum_required(VERSION 3.25)
project(IDSentinelTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Catch2 CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

include(CTest)
enable_testing()

add_executable(idsentinel_tests
    test_csv_parser.cpp
    test_reconciler.cpp
    test_compliance_store.cpp
    test_config.cpp
    test_source_validator.cpp
    test_network_connector.cpp
    test_logging.cpp
    test_cli.cpp
    test_process_lock.cpp
    mocks/MockViolationStore.cpp
)

target_include_directories(idsentinel_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

target_link_libraries(idsentinel_tests PRIVATE
    IDSentinelLib
    Catch2::Catch2WithMain
    spdlog::spdlog
    tomlplusplus::tomlplusplus
    fmt::fmt
    nlohmann_json::nlohmann_json
    SQLite::SQLite3
    OpenSSL::Crypto
)

add_test(NAME idsentinel_tests COMMAND idsentinel_tests)