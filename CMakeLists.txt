cmake_minimum_required(VERSION 3.25)
project(IDSentinel VERSION 1.0.0 LANGUAGES CXX)

# --- 1. Toolchain Setup ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Generate 'compile_commands.json' (Critical for VS Code / CLion IntelliSense)
set(CMAKE_EXPORT_COMPILE_COMPILE_COMMANDS ON)

# --- 2. Compiler Warnings ---
if(MSVC)
    add_compile_options(/W4 /permissive- /std:c++latest)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference -Wdouble-promotion -Wformat=2)
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
set(SOURCES
    src/main.cpp
    src/cli/CLI.cpp
    src/config/Config.cpp
    src/core/Logging.cpp
    src/core/Reconciler.cpp
    src/connectors/NetworkConnector.cpp
    src/parsers/CSVParser.cpp
    src/persistence/ComplianceStore.cpp
)

# --- 5. Build Target ---
add_executable(IDSentinel ${SOURCES})

# --- 6. Include Paths ---
target_include_directories(IDSentinel
    PRIVATE
        src
)

# --- 7. Linkage ---
target_link_libraries(IDSentinel
    PRIVATE
        CURL::libcurl
        SQLite::SQLite3
        OpenSSL::Crypto
        spdlog::spdlog
        CLI11::CLI11
        tomlplusplus::tomlplusplus
        fmt::fmt
        nlohmann_json::nlohmann_json
)

# --- 8. Output Management ---
set_target_properties(IDSentinel PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# --- 9. Testing ---
enable_testing()
if(BUILD_TESTING)
    find_package(Catch2 CONFIG REQUIRED)
    add_subdirectory(tests)
endif()