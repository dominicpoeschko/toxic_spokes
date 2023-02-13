#define termios asmtermios
#include <sys/ioctl.h>
#undef termios
#include "toxic_spokes/detail/raise.hpp"

#include <asm-generic/ioctls.h>
#include <asm-generic/termbits.h>
namespace ts { namespace detail {
    extern void setCustomBaudrate(std::string const& interface, int fd, std::uint32_t baudRate);

    void setCustomBaudrate(std::string const& interface, int fd, std::uint32_t baudRate) {
        termios2 tio;

        if(-1 == ::ioctl(fd, TCGETS2, &tio)) {
            TS_RAISE_SYSTEM_ERROR(interface + " ioctl TCGETS2 failed");
        }

        tio.c_cflag &= ~CBAUD;
        tio.c_cflag |= BOTHER;
        tio.c_ispeed = baudRate;
        tio.c_ospeed = baudRate;

        if(-1 == ::ioctl(fd, TCSETS2, &tio)) {
            TS_RAISE_SYSTEM_ERROR(
              interface + " ioctl TCSETS2 failed probably bad baudrate "
              + std::to_string(baudRate));
        }
    }
}}   // namespace ts::detail
