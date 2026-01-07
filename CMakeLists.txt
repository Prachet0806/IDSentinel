cmake_minimum_required(VERSION 3.12) # Bumped to 3.12 for better SQLite support
project(IDSentinel VERSION 1.0 LANGUAGES CXX)

# --- 1. Toolchain Setup ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Generate 'compile_commands.json' (Critical for VS Code / CLion IntelliSense)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- 2. Compiler Warnings (The "Strict" Set) ---
if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion)
endif()

# --- 3. Dependencies ---
find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

# --- 4. Source Management ---
# Uses GLOB to find files automatically (Optional, but saves typing)
# file(GLOB_RECURSE SOURCES "src/*.cpp") 
# OR keep manual list (Safer, preferred in CI/CD):
set(SOURCES
    src/main.cpp
    src/core/Reconciler.cpp
    src/connectors/NetworkConnector.cpp
    src/parsers/CSVParser.cpp
    src/persistence/ComplianceStore.cpp
)

# --- 5. Build Target ---
add_executable(IDSentinel ${SOURCES})

# --- 6. Include Paths ---
# TIP: Usually just including 'src' is enough if you write #include "core/Reconciler.h"
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
)

# --- 8. Output Management ---
# Puts the executable in a neat 'bin' folder
set_target_properties(IDSentinel PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)