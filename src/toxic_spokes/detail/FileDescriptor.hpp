#pragma once

#include "toxic_spokes/detail/chrono_helper.hpp"
#include "toxic_spokes/detail/raise.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <numeric>
#include <optional>
#include <span>
#include <sys/poll.h>
#include <unistd.h>
#include <vector>

namespace ts {

class FileDescriptor {
protected:
    int fd_{-1};

public:
    struct Polls {
        bool in{false};
        bool out{false};
        bool error{false};
        bool pri{false};
    };

    struct PollContext {
    private:
        std::vector<pollfd> storage;

    public:
        Polls poll{.in = true, .error = true};
        Polls call{.in = true};
        friend FileDescriptor;
    };

    class View {
    private:
        int fd_;
        View(int fd) noexcept : fd_{fd} {}

    public:
        friend FileDescriptor;

        bool operator==(View const& other) const noexcept = default;
    };

    FileDescriptor() noexcept = default;
    explicit FileDescriptor(int fd) noexcept : fd_{fd} {}

    FileDescriptor(FileDescriptor const& other)            = delete;
    FileDescriptor& operator=(FileDescriptor const& other) = delete;

    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if(this != std::addressof(other)) {
            reassign(other.fd_);
            other.fd_ = -1;
        }
        return *this;
    }

    ~FileDescriptor() noexcept { close(); }

    template<typename T>
    friend bool operator==(FileDescriptor const& v, T const& t) noexcept {
        return View{v} == t;
    }
    template<typename T>
    friend bool operator!=(FileDescriptor const& v, T const& t) noexcept {
        return !(v == t);
    }
    template<typename T>
    friend bool operator==(T const& t, FileDescriptor const& v) noexcept {
        return v == t;
    }

    template<typename T>
    friend bool operator!=(T const& t, FileDescriptor const& v) noexcept {
        return !(t == v);
    }

    explicit operator View() noexcept { return FileDescriptor::View{this->fd_}; }
    explicit operator const View() const noexcept { return FileDescriptor::View{this->fd_}; }

    void reassign(int new_fd) noexcept {
        close();
        fd_ = new_fd;
    }

    int release() noexcept {
        int fd = fd_;
        fd_    = -1;
        return fd;
    }

    bool is_valid() const noexcept { return fd_ != -1; }

    template<typename Rep, typename Period>
    bool can_recv(std::chrono::duration<Rep, Period> const& timeout) {
        Polls ps{};
        ps.in = true;
        return poll(timeout, ps);
    }

    template<typename Rep, typename Period>
    bool can_send(std::chrono::duration<Rep, Period> const& timeout) {
        Polls ps{};
        ps.out = true;
        return poll(timeout, ps);
    }

    template<typename Rep, typename Period>
    bool poll(std::chrono::duration<Rep, Period> const& timeout, Polls const& polls) {
        pollfd pfd;
        pfd.fd = fd();

        return poll_(
          ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout),
          std::span{std::addressof(pfd), 1},
          polls);
    }

    int  fd() const noexcept { return fd_; }
    void close() noexcept {
        if(is_valid()) {
            int const status = ::close(fd_);
            fd_              = -1;
            // On linux close will always close even on failure and errno EINTR
            if(-1 == status) {
                try {
                    TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("close failed");
                } catch(...) {
                }
            }
        }
    }

public:
    template<typename Rep, typename Periode, typename... SocketRanges>
    static void poll(
      std::chrono::duration<Rep, Periode> const& timeout,
      PollContext&                               context,
      SocketRanges... socketRanges) {
        std::size_t numFds
          = (static_cast<std::size_t>(std::distance(socketRanges.first, socketRanges.last)) + ...);

        context.storage.clear();
        context.storage.reserve(numFds);

        auto addFDs = [&](auto first, auto last, auto conv) {
            while(first != last) {
                pollfd pfd{};
                pfd.fd = View{conv(*first)}.fd_;
                context.storage.push_back(pfd);
                ++first;
            }
        };

        (addFDs(socketRanges.first, socketRanges.last, socketRanges.convert), ...);

        if(!poll_(
             ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout),
             std::span{context.storage},
             context.poll))
        {
            return;
        }

        auto handle
          = [&, current = context.storage.begin()](auto first, auto last, auto f) mutable {
                while(first != last) {
                    if(isPoll(*current, context.call)) {
                        f(*first);
                    }
                    ++current;
                    ++first;
                }
            };

        (handle(socketRanges.first, socketRanges.last, socketRanges.callback), ...);
    }

private:
    static bool isIn(pollfd const& pfd) { return (pfd.revents & POLLIN) != 0; }

    static bool isOut(pollfd const& pfd) { return (pfd.revents & POLLOUT) != 0; }

    static bool isError(pollfd const& pfd) {
        return
#ifdef POLLRDHUP
          ((pfd.revents & POLLRDHUP) != 0) ||
#endif
          ((pfd.revents & POLLERR) != 0) || ((pfd.revents & POLLHUP) != 0);
    }

    static bool isPri(pollfd const& pfd) { return (pfd.revents & POLLPRI) != 0; }

    static bool isAny(pollfd const& pfd) {
        return isIn(pfd) || isOut(pfd) || isError(pfd) || isPri(pfd);
    }

    static bool isPoll(pollfd const& pfd, Polls const& polls) {
        return (polls.error && isError(pfd)) || (polls.in && isIn(pfd)) || (polls.out && isOut(pfd))
            || (polls.pri && isPri(pfd));
    }

    static bool
    poll_(std::chrono::nanoseconds timeout, std::span<pollfd> storage, Polls const& polls) {
        timeout     = std::chrono::nanoseconds{} > timeout ? std::chrono::nanoseconds{} : timeout;
        auto calcTs = [](std::chrono::nanoseconds timeout_) {
            timeout_
              = std::chrono::nanoseconds{} > timeout_ ? std::chrono::nanoseconds{} : timeout_;
            std::chrono::seconds const sec
              = std::chrono::duration_cast<std::chrono::seconds>(timeout_);
            timespec ts{};
            if(sec.count() >= std::numeric_limits<decltype(ts.tv_sec)>::max()) {
                ts.tv_sec  = std::numeric_limits<decltype(ts.tv_sec)>::max();
                ts.tv_nsec = 0;
            } else {
                ts.tv_sec  = static_cast<decltype(ts.tv_sec)>(sec.count());
                ts.tv_nsec = static_cast<decltype(ts.tv_nsec)>(
                  std::chrono::duration_cast<std::chrono::nanoseconds>(timeout_ - sec).count());
            }
            return ts;
        };

        decltype(pollfd{}.events) events = 0;

        if(polls.in) {
            events |= POLLIN;
        }
        if(polls.out) {
            events |= POLLOUT;
        }
        if(polls.pri) {
            events |= POLLPRI;
        }
#ifdef POLLRDHUP
        if(polls.error) {
            events |= POLLRDHUP;
        }
#endif

        for(auto& pfd : storage) {
            pfd.events  = events;
            pfd.revents = 0;
        }

        auto const stoptime
          = timeout > std::chrono::hours(24 * 365 * 100)
            ? std::chrono::steady_clock::time_point::max()
            : std::chrono::steady_clock::now()
                + timeout;   // could overflow but the program run for ~191 years so that is OK

        auto ts = calcTs(timeout);

        auto doPoll = [&]() {
#ifdef __GNU_SOURCE
            return ::ppoll(storage.data(), storage.size(), std::addressof(ts), nullptr);
#else
            return ::poll(
              storage.data(),
              storage.size(),
              static_cast<int>(ts.tv_sec * 1000 + ts.tv_nsec / 1000000));
#endif
        };

        while(true) {
            int const status = doPoll();
            if(status == -1) {
                if(errno == EINTR) {
                    if(stoptime != std::chrono::steady_clock::time_point::max()) {
                        auto const now = std::chrono::steady_clock::now();
                        if(now >= stoptime) {
                            return false;
                        }
                        ts = calcTs(
                          std::chrono::duration_cast<std::chrono::nanoseconds>(stoptime - now));
                    }
                    continue;
                }
                TS_RAISE_SYSTEM_ERROR("ppoll failed");
            } else if(status == 0) {
                auto const now = std::chrono::steady_clock::now();
                if(now < stoptime) {
                    ts = calcTs(
                      std::chrono::duration_cast<std::chrono::nanoseconds>(stoptime - now));
                    continue;
                }
                return false;
            } else {
                bool ret = false;
                for(auto const& pfd : storage) {
                    if((pfd.revents & POLLNVAL) != 0) {
                        TS_RAISE(std::runtime_error, "poll_ failed POLLNVAL");
                    }

                    if(isAny(pfd)) {
                        ret = true;
                    }
                }
                return ret;
            }
        }
    }
};

template<typename I, typename CallbackF, typename ConvertF>
struct SocketRange {
    I         first;
    I         last;
    CallbackF callback;
    ConvertF  convert;

    SocketRange(I first_, I last_, CallbackF callback_, ConvertF convert_)
      : first{first_}
      , last{last_}
      , callback{callback_}
      , convert{convert_} {}

    SocketRange(I first_, I last_, CallbackF callback_)
      : SocketRange{
        first_,
        last_,
        callback_,
        [](std::add_lvalue_reference_t<decltype(*std::declval<I>())> c)
          -> std::add_lvalue_reference_t<decltype(*std::declval<I>())> { return c; }} {}

    template<typename S>
    SocketRange(S& socket, CallbackF callback_, ConvertF convert_)
      : SocketRange{&socket, std::next(&socket), callback_, convert_} {}

    template<typename S>
    SocketRange(S& socket, CallbackF callback_)
      : SocketRange{&socket, std::next(&socket), callback_} {}
};

template<typename I, typename CallbackF, typename ConvertF>
SocketRange(I, I, CallbackF, ConvertF) -> SocketRange<I, CallbackF, ConvertF>;

template<typename S, typename CallbackF, typename ConvertF>
SocketRange(S&, CallbackF, ConvertF) -> SocketRange<std::add_pointer_t<S>, CallbackF, ConvertF>;

template<typename I, typename CallbackF>
SocketRange(I, I, CallbackF) -> SocketRange<
  I,
  CallbackF,
  std::add_lvalue_reference_t<decltype(*std::declval<I>())> (*)(
    std::add_lvalue_reference_t<decltype(*std::declval<I>())>)>;

template<typename S, typename CallbackF>
SocketRange(S&, CallbackF) -> SocketRange<std::add_pointer_t<S>, CallbackF, S& (*)(S&)>;

}   // namespace ts
