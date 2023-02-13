#include "toxic_spokes/detail/FileDescriptor.hpp"
#include "toxic_spokes/detail/ScopeGuard.hpp"
#include "toxic_spokes/detail/system_call_helper.hpp"

#include <cstddef>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

namespace ts {
namespace detail {
    void setCustomBaudrate(std::string const& interface, int fd, std::uint32_t baudRate);
}

struct Serial {
private:
    FileDescriptor file_descriptor_{};
    termios        initialtio{};

    struct BL {
        std::uint32_t baudRate{};
        speed_t       speed{};
    };
    static constexpr std::array BaudLookup{
#ifdef B0
      BL{      0,       B0},
#endif
#ifdef B50
      BL{     50,      B50},
#endif
#ifdef B75
      BL{     75,      B75},
#endif
#ifdef B110
      BL{    110,     B110},
#endif
#ifdef B150
      BL{    150,     B150},
#endif
#ifdef B200
      BL{    200,     B200},
#endif
#ifdef B300
      BL{    300,     B300},
#endif
#ifdef B600
      BL{    600,     B600},
#endif
#ifdef B1200
      BL{   1200,    B1200},
#endif
#ifdef B1800
      BL{   1800,    B1800},
#endif
#ifdef B2400
      BL{   2400,    B2400},
#endif
#ifdef B4800
      BL{   4800,    B4800},
#endif
#ifdef B9600
      BL{   9600,    B9600},
#endif
#ifdef B19200
      BL{  19200,   B19200},
#endif
#ifdef B38400
      BL{  38400,   B38400},
#endif
#ifdef B57600
      BL{  57600,   B57600},
#endif
#ifdef B115200
      BL{ 115200,  B115200},
#endif
#ifdef B230400
      BL{ 230400,  B230400},
#endif
#ifdef B460800
      BL{ 460800,  B460800},
#endif
#ifdef B500000
      BL{ 500000,  B500000},
#endif
#ifdef B576000
      BL{ 576000,  B576000},
#endif
#ifdef B921600
      BL{ 921600,  B921600},
#endif
#ifdef B1000000
      BL{1000000, B1000000},
#endif
#ifdef B1152000
      BL{1152000, B1152000},
#endif
#ifdef B1500000
      BL{1500000, B1500000},
#endif
#ifdef B2000000
      BL{2000000, B2000000},
#endif
#ifdef B2500000
      BL{2500000, B2500000},
#endif
#ifdef B3000000
      BL{3000000, B3000000},
#endif
#ifdef B3500000
      BL{3500000, B3500000},
#endif
#ifdef B4000000
      BL{4000000, B4000000},
#endif
      BL{      0,        0}
    };

    void modify_flag(int flag, bool set) {
        auto const oldFlag = ::fcntl(file_descriptor_.fd(), F_GETFL);
        if(oldFlag == -1) {
            TS_RAISE_SYSTEM_ERROR("fcntl failed");
        }

        int const newFlag = set ? (oldFlag | flag) : (oldFlag & (~flag));

        if(-1 == ::fcntl(file_descriptor_.fd(), F_SETFL, newFlag)) {
            TS_RAISE_SYSTEM_ERROR("fcntl failed");
        }
        auto const readBack = ::fcntl(file_descriptor_.fd(), F_GETFL);
        if(-1 == readBack) {
            TS_RAISE_SYSTEM_ERROR("fcntl failed");
        }

        if(readBack != newFlag) {
            TS_RAISE_PRINT_ONLY(
              std::runtime_error,
              std::string{"flag missmatch old: "} + std::to_string(oldFlag)
                + " request: " + std::to_string(newFlag) + " redback: " + std::to_string(readBack));
        }
    }

    void set_noneBlocking() { modify_flag(O_NONBLOCK, true); }
    void set_blocking() { modify_flag(O_NONBLOCK, false); }

public:
    using Fd_t = FileDescriptor;

    explicit operator FileDescriptor::View() noexcept {
        return FileDescriptor::View{file_descriptor_};
    }
    explicit operator FileDescriptor::View const() const noexcept {
        return FileDescriptor::View{file_descriptor_};
    }

    constexpr bool is_defaultBaudRate(std::uint32_t baudRate) {
        auto const it = std::find_if(BaudLookup.begin(), BaudLookup.end(), [&](BL const& bl) {
            return bl.baudRate == baudRate;
        });
        if(it == BaudLookup.end()) {
            return false;
        }
        return it->speed != B0;
    }

    ~Serial() {
        if(file_descriptor_.is_valid()) {
            if(-1 == ::tcsetattr(file_descriptor_.fd(), TCSANOW, std::addressof(initialtio))) {
                TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("tcsetattr failed");
            }
        }
    }

    Serial(Serial const&)            = delete;
    Serial(Serial&&)                 = default;
    Serial& operator=(Serial const&) = delete;
    Serial& operator=(Serial&&)      = default;

    Serial(std::string const& interface, std::uint32_t baudRate)
      : file_descriptor_{::open(interface.c_str(), O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK)} {
        if(!file_descriptor_.is_valid()) {
            TS_RAISE_SYSTEM_ERROR(interface + " open failed");
        }

        if(-1 == ::tcgetattr(file_descriptor_.fd(), std::addressof(initialtio))) {
            TS_RAISE_SYSTEM_ERROR(interface + " tcgetattr failed");
        }

        bool const br_default = is_defaultBaudRate(baudRate);

        termios tio{};

        tio.c_iflag = 0;
        tio.c_oflag = 0;
        tio.c_cflag = CS8 | CREAD | CLOCAL;
        tio.c_lflag = 0;

        tio.c_cc[VMIN]  = 0;
        tio.c_cc[VTIME] = 0;

        ::cfmakeraw(std::addressof(tio));

        if(br_default) {
            speed_t const speed
              = std::find_if(BaudLookup.begin(), BaudLookup.end(), [&](BL const& bl) {
                    return bl.baudRate == baudRate;
                })->speed;

            if(-1 == ::cfsetospeed(std::addressof(tio), speed)) {
                TS_RAISE_SYSTEM_ERROR(interface + " cfsetospeed failed");
            }
            if(-1 == ::cfsetispeed(std::addressof(tio), speed)) {
                TS_RAISE_SYSTEM_ERROR(interface + " cfsetispeed failed");
            }
        }

        if(-1 == ::tcsetattr(file_descriptor_.fd(), TCSANOW, std::addressof(tio))) {
            TS_RAISE_SYSTEM_ERROR(interface + " tcsetattr failed");
        }

        termios readtio{};
        if(-1 == ::tcgetattr(file_descriptor_.fd(), std::addressof(readtio))) {
            TS_RAISE_SYSTEM_ERROR(interface + " tcgetattr failed");
        }

        if(
          (readtio.c_iflag != tio.c_iflag) || (readtio.c_oflag != tio.c_oflag)
          || (readtio.c_cflag != tio.c_cflag) || (readtio.c_lflag != tio.c_lflag)
          || (::cfgetispeed(&readtio) != ::cfgetispeed(std::addressof(tio)))
          || (::cfgetospeed(std::addressof(readtio)) != ::cfgetospeed(std::addressof(tio)))
          || (readtio.c_cc[VMIN] != tio.c_cc[VMIN]) || (readtio.c_cc[VTIME] != tio.c_cc[VTIME]))
        {
            TS_RAISE(std::runtime_error, interface + " create failed (termios missmatch)");
        }

        if(!br_default) {
            detail::setCustomBaudrate(interface, file_descriptor_.fd(), baudRate);
        }
    }

    std::size_t send(std::span<std::byte const> buffer) {
        set_blocking();
        auto guard
          = make_scope_guard([this]() { set_noneBlocking(); }, ScopeGuardCallPolicy::always);

        if(buffer.empty()) {
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "send failed");
        }
        std::size_t const size = buffer.size();
        while(!buffer.empty()) {
            auto const send = send_nonblocking(buffer);
            buffer          = buffer.subspan(send);
        }
        return size;
    }

    std::size_t send_nonblocking(std::span<std::byte const> buffer) {
        if(buffer.empty()) {
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "send_nonblocking failed");
        }
        auto const status = ::write(file_descriptor_.fd(), buffer.data(), buffer.size());
        if(-1 == status) {
            if(ts::detail::is_errno_recoverable(errno)) {
                return 0;
            }
            TS_RAISE(std::runtime_error, "read failed");
        }
        return static_cast<std::size_t>(status);
    }

    std::size_t recv(std::span<std::byte> buffer) {
        set_blocking();
        auto guard
          = make_scope_guard([this]() { set_noneBlocking(); }, ScopeGuardCallPolicy::always);
        if(buffer.empty()) {
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "recv failed");
        }
        std::size_t const size = buffer.size();
        while(!buffer.empty()) {
            auto const send = recv_nonblocking(buffer);
            buffer          = buffer.subspan(send);
        }
        return size;
    }

    std::size_t recv_nonblocking(std::span<std::byte> buffer) {
        if(buffer.empty()) {
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "recv_nonblocking failed");
        }
        auto const status = ::read(file_descriptor_.fd(), buffer.data(), buffer.size());
        if(-1 == status) {
            if(ts::detail::is_errno_recoverable(errno)) {
                return 0;
            }
            TS_RAISE(std::runtime_error, "read failed");
        }
        return static_cast<std::size_t>(status);
    }

    bool is_valid() { return (-1 != ::fcntl(file_descriptor_.fd(), F_GETFD)); }

    std::size_t bytes_available() {
        int bytesAv = 0;
        if(-1 == ::ioctl(file_descriptor_.fd(), FIONREAD, std::addressof(bytesAv))) {
            TS_RAISE_SYSTEM_ERROR("ioctl(FIONREAD) failed");
        }
        if(0 > bytesAv) {
            TS_RAISE_SYSTEM_ERROR_CE(ERANGE, "ioctl(FIONREAD) failed");
        }
        return static_cast<std::size_t>(bytesAv);
    }

    template<typename Rep, typename Period>
    bool can_recv(std::chrono::duration<Rep, Period> const& timeout) {
        return file_descriptor_.can_recv(timeout);
    }

    template<typename Rep, typename Period>
    bool can_send(std::chrono::duration<Rep, Period> const& timeout) {
        return file_descriptor_.can_send(timeout);
    }
};

}   // namespace ts
