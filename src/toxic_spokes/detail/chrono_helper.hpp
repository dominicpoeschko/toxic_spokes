#pragma once

#include <chrono>
#include <sys/time.h>
#include <type_traits>

namespace ts { namespace chrono {
    template<typename Duration, typename Rep, typename Period>
    auto saturating_duration_cast(std::chrono::duration<Rep, Period> d) ->
      typename std::enable_if<!std::is_same<Duration, decltype(d)>::value, Duration>::type {
        using S       = std::chrono::duration<double, typename Duration::period>;
        constexpr S m = Duration::min();
        constexpr S M = Duration::max();
        S const     s = d;
        if(s < m) {
            return Duration::min();
        }
        if(s > M) {
            return Duration::max();
        }
        return std::chrono::duration_cast<Duration>(s);
    }

    template<typename Duration>
    auto saturating_duration_cast(Duration d) {
        return d;
    }

    template<typename Rep, typename Period>
    auto clamp_to_positive(std::chrono::duration<Rep, Period> duration) {
        using D = std::chrono::duration<Rep, Period>;
        return D{} > duration ? D{} : duration;
    }

    template<typename Rep, typename Period>
    auto to_timeval(std::chrono::duration<Rep, Period> duration) {
        using D                        = std::chrono::duration<Rep, Period>;
        duration                       = clamp_to_positive(duration);
        std::chrono::seconds const sec = std::chrono::duration_cast<std::chrono::seconds>(duration);
        timeval                    tv{};
        if(duration == D::max()) {
            tv.tv_sec  = 0;
            tv.tv_usec = 0;
            return tv;
        }

        if(duration == D{}) {
            tv.tv_sec  = 0;
            tv.tv_usec = 1;
        } else if(sec.count() >= std::numeric_limits<decltype(tv.tv_sec)>::max()) {
            tv.tv_sec  = std::numeric_limits<decltype(tv.tv_sec)>::max();
            tv.tv_usec = 0;
        } else {
            tv.tv_sec  = static_cast<decltype(tv.tv_sec)>(sec.count());
            tv.tv_usec = static_cast<decltype(tv.tv_usec)>(
              std::chrono::duration_cast<std::chrono::microseconds>(duration - sec).count());
        }

        if(tv.tv_sec == 0 && tv.tv_usec == 0) {
            tv.tv_usec = 1;
        }

        return tv;
    }

    template<typename Clock, typename Rep, typename Period>
    auto calc_stop_time(std::chrono::duration<Rep, Period> timeout) {
        timeout = clamp_to_positive(timeout);
        return timeout > std::chrono::hours(24 * 365 * 100)
               ? Clock::time_point::max()
               : Clock::now()
                   + timeout;   // could overflow but the program run for ~191 years so that is OK
    }

}}   // namespace ts::chrono
