#include "core/ProcessLock.h"
#include <spdlog/spdlog.h>

#ifndef _WIN32
#include <sys/file.h>
#include <cerrno>
#include <cstring>
#endif

ProcessLock::ProcessLock(const std::filesystem::path& lockPath)
    : lockPath_(lockPath) {}

ProcessLock::~ProcessLock() {
#ifdef _WIN32
    if (held_ && handle_ != INVALID_HANDLE_VALUE) {
        UnlockFile(handle_, 0, 0, MAXDWORD, MAXDWORD);
    }
    if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
    }
#else
    if (held_ && fd_ >= 0) {
        flock(fd_, LOCK_UN);
    }
    if (fd_ >= 0) {
        close(fd_);
    }
#endif
}

Result<bool> ProcessLock::tryAcquire() {
#ifdef _WIN32
    if (!lockPath_.parent_path().empty()) {
        std::error_code ec;
        std::filesystem::create_directories(lockPath_.parent_path(), ec);
        if (ec) {
            return Result<bool>::err(Error{ "LOCK_IO", "Cannot create lock directory: " + ec.message() });
        }
    }
    handle_ = CreateFileW(lockPath_.wstring().c_str(), GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
        return Result<bool>::err(Error{ "LOCK_IO", "Cannot open lock file" });
    }
    OVERLAPPED ov = {};
    if (!LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0, MAXDWORD, MAXDWORD, &ov)) {
        DWORD err = GetLastError();
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        if (err == ERROR_LOCK_VIOLATION) {
            return Result<bool>::ok(false); // Another process holds it.
        }
        return Result<bool>::err(Error{ "LOCK_IO", "Cannot acquire lock, error " + std::to_string(err) });
    }
    held_ = true;
    return Result<bool>::ok(true);
#else
    if (!lockPath_.parent_path().empty()) {
        std::error_code ec;
        std::filesystem::create_directories(lockPath_.parent_path(), ec);
        if (ec) {
            return Result<bool>::err(Error{ "LOCK_IO", "Cannot create lock directory: " + ec.message() });
        }
    }
    fd_ = open(lockPath_.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd_ < 0) {
        return Result<bool>::err(Error{ "LOCK_IO", std::string("Cannot open lock file: ") + std::strerror(errno) });
    }
    if (flock(fd_, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            close(fd_);
            fd_ = -1;
            return Result<bool>::ok(false); // Another process holds it.
        }
        int saved = errno;
        close(fd_);
        fd_ = -1;
        return Result<bool>::err(Error{ "LOCK_IO", std::string("Cannot acquire lock: ") + std::strerror(saved) });
    }
    held_ = true;
    return Result<bool>::ok(true);
#endif
}
