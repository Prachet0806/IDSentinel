#pragma once
#include "core/Result.h"
#include <filesystem>
#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// Exclusive, non-blocking, cross-process lock guarding one governance
// database. Two concurrent writers could interleave runs and corrupt the
// ledger's run accounting, so the second process must fail fast instead of
// running. The lock is held for the guard's lifetime and released on
// destruction.
class ProcessLock {
public:
    explicit ProcessLock(const std::filesystem::path& lockPath);
    ~ProcessLock();

    ProcessLock(const ProcessLock&) = delete;
    ProcessLock& operator=(const ProcessLock&) = delete;

    // Non-blocking acquire. Returns ok(true) when the lock is held,
    // ok(false) when another process holds it, err on I/O failure.
    Result<bool> tryAcquire();
    bool held() const { return held_; }

private:
    std::filesystem::path lockPath_;
    bool held_ = false;
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
};
