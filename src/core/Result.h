#pragma once
#include <variant>
#include <string>
#include <utility>
#include <functional>
#include <optional>
#include <cerrno>
#include <cstring>

struct Error {
    std::string code;
    std::string message;

    static Error fromErrno(const char* context) {
        return Error{ "ERRNO", std::string(context) + ": " + std::strerror(errno) };
    }
};

template<typename T, typename E = Error>
class Result {
    std::variant<T, E> storage_;

    Result(T&& value) : storage_(std::move(value)) {}
    Result(const T& value) : storage_(value) {}
    Result(E&& error) : storage_(std::move(error)) {}
    Result(const E& error) : storage_(error) {}

public:
    static Result ok(T value) { return Result(std::move(value)); }
    static Result err(E error) { return Result(std::move(error)); }

    [[nodiscard]] bool hasValue() const noexcept { return std::holds_alternative<T>(storage_); }
    [[nodiscard]] bool hasError() const noexcept { return std::holds_alternative<E>(storage_); }

    [[nodiscard]] T& value() & {
        if (!hasValue()) throw std::bad_variant_access();
        return std::get<T>(storage_);
    }
    [[nodiscard]] const T& value() const& {
        if (!hasValue()) throw std::bad_variant_access();
        return std::get<T>(storage_);
    }
    [[nodiscard]] T&& value() && {
        if (!hasValue()) throw std::bad_variant_access();
        return std::get<T>(std::move(storage_));
    }

    [[nodiscard]] E& error() & {
        if (!hasError()) throw std::bad_variant_access();
        return std::get<E>(storage_);
    }
    [[nodiscard]] const E& error() const& {
        if (!hasError()) throw std::bad_variant_access();
        return std::get<E>(storage_);
    }

    [[nodiscard]] T* operator->() { return hasValue() ? &std::get<T>(storage_) : nullptr; }
    [[nodiscard]] const T* operator->() const { return hasValue() ? &std::get<T>(storage_) : nullptr; }
    [[nodiscard]] T& operator*() & { return value(); }
    [[nodiscard]] const T& operator*() const& { return value(); }
    [[nodiscard]] T&& operator*() && { return std::move(value()); }

    template<typename F>
    [[nodiscard]] auto andThen(F&& f) & -> Result<decltype(f(std::declval<T&>()).value()), E> {
        using U = decltype(f(std::declval<T&>()).value());
        if (!hasValue()) return Result<U, E>::err(error());
        return f(value());
    }

    template<typename F>
    [[nodiscard]] auto andThen(F&& f) && -> Result<decltype(f(std::declval<T>()).value()), E> {
        using U = decltype(f(std::declval<T>()).value());
        if (!hasValue()) return Result<U, E>::err(std::move(error()));
        return f(std::move(value()));
    }

    template<typename F>
    [[nodiscard]] auto orElse(F&& f) & -> Result<T, E> {
        if (hasValue()) return *this;
        return f(error());
    }

    template<typename F>
    [[nodiscard]] auto orElse(F&& f) && -> Result<T, E> {
        if (hasValue()) return std::move(*this);
        return f(std::move(error()));
    }

    [[nodiscard]] std::optional<T> toOptional() & {
        if (hasValue()) return std::optional<T>(value());
        return std::nullopt;
    }
};

template<typename E>
class Result<void, E> {
    std::variant<std::monostate, E> storage_;

    Result() : storage_(std::monostate{}) {}
    Result(E&& error) : storage_(std::move(error)) {}
    Result(const E& error) : storage_(error) {}

public:
    static Result ok() { return Result(); }
    static Result err(E error) { return Result(std::move(error)); }

    [[nodiscard]] bool hasValue() const noexcept { return std::holds_alternative<std::monostate>(storage_); }
    [[nodiscard]] bool hasError() const noexcept { return std::holds_alternative<E>(storage_); }

    void value() const {
        if (!hasValue()) throw std::bad_variant_access();
    }

    [[nodiscard]] E& error() & {
        if (!hasError()) throw std::bad_variant_access();
        return std::get<E>(storage_);
    }
    [[nodiscard]] const E& error() const& {
        if (!hasError()) throw std::bad_variant_access();
        return std::get<E>(storage_);
    }

    template<typename F>
    [[nodiscard]] auto andThen(F&& f) & -> Result<decltype(f().value()), E> {
        if (!hasValue()) return Result<decltype(f().value()), E>::err(error());
        return f();
    }

    template<typename F>
    [[nodiscard]] auto andThen(F&& f) && -> Result<decltype(f().value()), E> {
        if (!hasValue()) return Result<decltype(f().value()), E>::err(std::move(error()));
        return f();
    }

    template<typename F>
    [[nodiscard]] auto orElse(F&& f) & -> Result<void, E> {
        if (hasValue()) return *this;
        return f(error());
    }
};