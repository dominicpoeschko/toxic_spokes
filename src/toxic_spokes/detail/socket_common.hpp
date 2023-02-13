#pragma once

#ifdef __linux__
    #include <linux/can.h>
#endif
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

namespace ts {
class IPAddress;
namespace Socket {
    enum class Protocol : int {
        DEFAULT = 0,
#ifdef IPPROTO_SCTP
        SCTP = IPPROTO_SCTP,
#endif
        UDP = IPPROTO_UDP,
        TCP = IPPROTO_TCP,
#ifdef CAN_RAW
        CAN = CAN_RAW
#endif
    };
    enum class Type : int {
        DGRAM     = SOCK_DGRAM,
        STREAM    = SOCK_STREAM,
        SEQPACKET = SOCK_SEQPACKET,
        RAW       = SOCK_RAW
    };
    enum class Domain : int {
        INET  = PF_INET,
        INET6 = PF_INET6,
#ifdef PF_UNIX
        UNIX = PF_UNIX,
#endif
#ifdef PF_CAN
        CAN = PF_CAN
#endif
    };

    constexpr bool is_packet_based_type(Type type) {
        return type == Type::DGRAM || type == Type::SEQPACKET;
    }

    struct AbstractSocket {
        inline explicit AbstractSocket(std::string name_) : name{std::move(name_)} {}
        std::string name;
    };
}   // namespace Socket

namespace IP {
    enum class Type {
        Any,
        IPv4,
        IPv6,
    };
}   // namespace IP

}   // namespace ts
