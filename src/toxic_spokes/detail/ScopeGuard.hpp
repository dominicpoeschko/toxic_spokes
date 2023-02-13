#pragma once

#include "toxic_spokes/detail/raise.hpp"

#include <exception>
#include <functional>
namespace ts {

enum class ScopeGuardCallPolicy { always, no_exception, exception, never };
template<typename F>
struct ScopeGuard {
public:
    ScopeGuard(F&& f, ScopeGuardCallPolicy p)
      : f_{std::forward<F>(f)}
      , policy_{p}
#ifdef __cpp_lib_uncaught_exceptions
      , exceptionsAtStart_{std::uncaught_exceptions()}
#endif
    {
    }

    ScopeGuard(ScopeGuard const& other)                = delete;
    ScopeGuard& operator=(ScopeGuard const& other)     = delete;
    ScopeGuard(ScopeGuard&& other) noexcept            = default;
    ScopeGuard& operator=(ScopeGuard&& other) noexcept = default;

    ~ScopeGuard() noexcept {
        if(policy_ != ScopeGuardCallPolicy::never
           && (policy_ == ScopeGuardCallPolicy::always
               || (
#ifdef __cpp_lib_uncaught_exceptions
                 (std::uncaught_exceptions() > exceptionsAtStart_)
#else
                 std::uncaught_exception()
#endif
                 && (policy_ == ScopeGuardCallPolicy::exception))))
        {
            try {
                f_();
            } catch(std::exception const& e) {
                TS_LOG(e.what());
            } catch(...) {
                TS_LOG("catched ...");
            }
        }
    }

    void setPolicy(ScopeGuardCallPolicy p) noexcept { policy_ = p; }

private:
    F                    f_;
    ScopeGuardCallPolicy policy_;
#ifdef __cpp_lib_uncaught_exceptions
    int exceptionsAtStart_;
#endif
};

template<typename F>
ScopeGuard<std::decay_t<F>> make_scope_guard(F&& f, ScopeGuardCallPolicy p) {
    return {std::forward<F>(f), p};
}
}   // namespace ts
