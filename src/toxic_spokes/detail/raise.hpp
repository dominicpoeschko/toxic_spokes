#pragma once

#include <string>
#include <system_error>
#include <utility>

namespace ts {
namespace detail {

    template<typename Exception, typename... Args>
    [[noreturn, gnu::noinline]] void raise(Args&&... args) {
        throw Exception(std::forward<Args>(args)...);
    }

    template<typename Exception, typename... Args>
    std::string get_what(Args&&... args) {
        return Exception(std::forward<Args>(args)...).what();
    }

}   // namespace detail

#ifndef TS_LOG

    #define TS_STRRCHR(str, sep) static_cast<char const*>(__builtin_strrchr(str, sep))

    #define TS_STRINGIFY(x) #x
    #define TS_TOSTRING(x)  TS_STRINGIFY(x)

    #define TS_AT()                                                 \
        TS_STRRCHR("/" __FILE__ ":" TS_TOSTRING(__LINE__) " ", '/') \
        +1
    #define TS_LOG(s)                    \
        do {                             \
            std::fputs(TS_AT(), stderr); \
            std::fputs(s, stderr);       \
            std::fputs("\n", stderr);    \
        } while(false)
#endif

#define TS_RAISE_PRINT_INTERNAL(prefix, exception, ...) \
    TS_LOG(std::string{                                 \
      prefix "throwing " #exception " with what(): "    \
      + ts::detail::get_what<exception>(__VA_ARGS__)}   \
             .c_str())

#define TS_RAISE_PRINT_ONLY(exception, ...) TS_RAISE_PRINT_INTERNAL("not ", exception, __VA_ARGS__)

#define TS_RAISE(exception, ...)                         \
    TS_RAISE_PRINT_INTERNAL("", exception, __VA_ARGS__); \
    ts::detail::raise<exception>(__VA_ARGS__)

#define TS_RAISE_MAYBE_SILENT(silent, exception, ...)        \
    if(!(silent)) {                                          \
        TS_RAISE_PRINT_INTERNAL("", exception, __VA_ARGS__); \
    }                                                        \
    ts::detail::raise<exception>(__VA_ARGS__)

#define TS_RAISE_SYSTEM_ERROR_CE(num, msg) \
    TS_RAISE(std::system_error, (num), std::system_category(), (msg))

#define TS_RAISE_SYSTEM_ERROR_CE_MAYBE_SILENT(silent, num, msg) \
    TS_RAISE_MAYBE_SILENT(silent, std::system_error, (num), std::system_category(), (msg))

#define TS_RAISE_SYSTEM_ERROR_CE_PRINT_ONLY(num, msg) \
    TS_RAISE_PRINT_ONLY(std::system_error, (num), std::system_category(), (msg))

#define TS_RAISE_SYSTEM_ERROR(msg)                                            \
    do {                                                                      \
        auto TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO = errno;                     \
        (void)TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO;                            \
        TS_RAISE_SYSTEM_ERROR_CE(TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO, (msg)); \
    } while(false)

#define TS_RAISE_SYSTEM_ERROR_MAYBE_SILENT(silent, msg)                                            \
    do {                                                                                           \
        auto TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO = errno;                                          \
        (void)TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO;                                                 \
        TS_RAISE_SYSTEM_ERROR_CE_MAYBE_SILENT(silent, TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO, (msg)); \
    } while(false)

#define TS_RAISE_SYSTEM_ERROR_PRINT_ONLY(msg)                                            \
    do {                                                                                 \
        auto TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO = errno;                                \
        (void)TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO;                                       \
        TS_RAISE_SYSTEM_ERROR_CE_PRINT_ONLY(TS_RAISE_DO_NOT_USE_THIS_NAME_ERRNO, (msg)); \
    } while(false)

}   // namespace ts
