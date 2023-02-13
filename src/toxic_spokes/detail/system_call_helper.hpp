#pragma once

#include <cerrno>
#include <functional>

namespace ts { namespace detail {
    template<std::size_t count, typename EType, typename F, typename... Args>
    EType retry_on_errno(EType errorVal, int errnoRetryValue, F&& f, Args&&... args) {
        std::size_t retrys{};
        while(true) {
            auto ret = f(std::forward<Args>(args)...);
            if(ret == errorVal) {
                if(errno != errnoRetryValue) {
                    return ret;
                }
            } else {
                return ret;
            }
            if(retrys == count) {
                return ret;
            }
            ++retrys;
        }
    }

    template<std::size_t count, typename EType, typename F, typename... Args>
    EType retry_on_return(EType errorVal, F&& f, Args&&... args) {
        std::size_t retrys{};
        while(true) {
            auto ret = f(std::forward<Args>(args)...);
            if(ret != errorVal) {
                return ret;
            }
            if(retrys == count) {
                return ret;
            }
            ++retrys;
        }
    }

    static inline bool is_errno_recoverable(int errnoToCheck) {
        return errnoToCheck == EAGAIN || (EWOULDBLOCK != EAGAIN && errnoToCheck == EWOULDBLOCK)
            || errnoToCheck == EINTR;
    }

    static inline bool isflagSet(int value, int flag) { return (value & flag) != 0; }
    static inline int  clearflag(int flags, int flag) { return flags & ~(flag); }
    static inline int  setflag(int flags, int flag) { return flags | flag; }
}}   // namespace ts::detail
