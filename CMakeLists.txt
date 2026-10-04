cmake_minimum_required(VERSION 3.25)
project(IDSentinel VERSION 1.0.0 LANGUAGES CXX)

# --- 1. Toolchain Setup ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Generate 'compile_commands.json' (Critical for VS Code / CLion IntelliSense)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- 2. Compiler Warnings ---
# NOTE: Do not pass /std:c++... manually; CMAKE_CXX_STANDARD already emits it.
# Manually adding /std:c++latest fights the generated flag (D9025) on MSVC.
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wsign-conversion -Wnull-dereference -Wdouble-promotion -Wformat=2)
endif()

# --- 3. Dependencies (vcpkg) ---
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# --- 4. Source Management ---
# NOTE: src/main.cpp is intentionally excluded from the library so that
# the Catch2 test binary (which provides its own main) can link IDSentinelLib.
set(IDSentinel_SOURCES
    src/cli/CLI.cpp
    src/config/Config.cpp
    src/core/Logging.cpp
    src/core/ProcessLock.cpp
    src/core/Reconciler.cpp
    src/core/SourceValidator.cpp
    src/core/Policy.cpp
    src/connectors/NetworkConnector.cpp
    src/parsers/CSVParser.cpp
    src/persistence/ComplianceStore.cpp
)

# --- 5. Build Library Target ---
add_library(IDSentinelLib ${IDSentinel_SOURCES})

target_include_directories(IDSentinelLib
    PUBLIC
        src
)

target_link_libraries(IDSentinelLib
    PUBLIC
        CURL::libcurl
        SQLite::SQLite3
        OpenSSL::Crypto
        spdlog::spdlog
        CLI11::CLI11
        tomlplusplus::tomlplusplus
        fmt::fmt
        nlohmann_json::nlohmann_json
)

# --- 6. Build Executable ---
add_executable(IDSentinel src/main.cpp)
target_link_libraries(IDSentinel PRIVATE IDSentinelLib)

# --- 7. Output Management ---
# NOTE: Visual Studio (multi-config) appends $(Configuration) automatically,
# so binaries land in build/bin/Release, build/bin/Debug, etc. Single-config
# generators (Make/Ninja) use build/bin directly. Consume via ctest -C.
set_target_properties(IDSentinel PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
)

# --- 8. Testing ---
option(BUILD_TESTING "Build tests" ON)
include(CTest)
enable_testing()
if(BUILD_TESTING)
    find_package(Catch2 CONFIG REQUIRED)
    add_subdirectory(tests)
endif()