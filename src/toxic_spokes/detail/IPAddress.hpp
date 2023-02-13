#pragma once

#include "toxic_spokes/detail/ScopeGuard.hpp"
#include "toxic_spokes/detail/raise.hpp"
#include "toxic_spokes/detail/socket_common.hpp"
#include "toxic_spokes/detail/system_call_helper.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>
#include <variant>
#include <vector>

namespace ts {

struct GAI_Error_Category : std::error_category {
    char const* name() const noexcept override { return "GAI"; }

    std::string message(int ev) const override {
#ifdef EAI_SYSTEM
        return ::gai_strerror(ev);
#else
        return "gai_error(" + std::to_string(ev) + ")";
#endif
    }
};
namespace detail {
    class Socket_Impl;
}
class IPAddress {
    friend class detail::Socket_Impl;

    static sockaddr* to_sockaddr(sockaddr_in* in4) { return reinterpret_cast<sockaddr*>(in4); }
    static sockaddr* to_sockaddr(sockaddr_in6* in6) { return reinterpret_cast<sockaddr*>(in6); }
    static sockaddr* to_sockaddr(sockaddr_storage* storage) {
        return reinterpret_cast<sockaddr*>(storage);
    }

    static sockaddr const* to_sockaddr(sockaddr_in const* in4) {
        return reinterpret_cast<sockaddr const*>(in4);
    }
    static sockaddr const* to_sockaddr(sockaddr_in6 const* in6) {
        return reinterpret_cast<sockaddr const*>(in6);
    }
    static sockaddr const* to_sockaddr(sockaddr_storage const* storage) {
        return reinterpret_cast<sockaddr const*>(storage);
    }

private:
    std::variant<sockaddr_in, sockaddr_in6> address_storage_;

    socklen_t size() const {
        if(isIPv4()) {
            return sizeof(sockaddr_in);
        }
        return sizeof(sockaddr_in6);
    }

    int address_familie() const {
        if(isIPv4()) {
            return AF_INET;
        }

        return AF_INET6;
    }

    sockaddr const* get_sockaddr_ptr() const {
        if(isIPv4()) {
            return reinterpret_cast<sockaddr const*>(std::addressof(as4()));
        }
        return reinterpret_cast<sockaddr const*>(std::addressof(as6()));
    }

    sockaddr_in const& get_sockaddr_in() const {
        if(!isIPv4()) {
            TS_RAISE(std::runtime_error, "getsockaddr_in on IPAddress not of type IPv4");
        }
        return as4();
    }
    sockaddr_in6 const& get_sockaddr_in6() const {
        if(!isIPv6()) {
            TS_RAISE(std::runtime_error, "getsockaddr_in on IPAddress not of type IPv6");
        }
        return as6();
    }

    sockaddr_in const&  as4() const { return std::get<sockaddr_in>(address_storage_); }
    sockaddr_in6 const& as6() const { return std::get<sockaddr_in6>(address_storage_); }
    sockaddr_in&        as4() { return std::get<sockaddr_in>(address_storage_); }
    sockaddr_in6&       as6() { return std::get<sockaddr_in6>(address_storage_); }

    static sockaddr_in defaultV4() {
        sockaddr_in ret{};
        //TODO        ret.sin_len    = sizeof(sockaddr_in);
        ret.sin_family = AF_INET;
        return ret;
    }

    static sockaddr_in6 defaultV6() {
        sockaddr_in6 ret{};
        //TODO        ret.sin6_len    = sizeof(sockaddr_in6);
        ret.sin6_family = AF_INET6;
        return ret;
    }

    explicit IPAddress(addrinfo const& info) : IPAddress{info, info.ai_addrlen} {}

    template<typename T>
        requires std::is_same_v<T, sockaddr> || std::is_same_v<T, sockaddr_storage>
              || std::is_same_v<T, addrinfo>
    IPAddress(T const& v, socklen_t length) : IPAddress() {
        auto const& family = [&]() {
            if constexpr(std::is_same_v<T, sockaddr>) {
                return v.sa_family;
            } else if constexpr(std::is_same_v<T, sockaddr_storage>) {
                return v.ss_family;
            } else {
                return v.ai_family;
            }
        }();
        auto const* storage = [&]() {
            if constexpr(std::is_same_v<T, sockaddr>) {
                return std::addressof(v);
            } else if constexpr(std::is_same_v<T, sockaddr_storage>) {
                return std::addressof(v);
            } else {
                return v.ai_addr;
            }
        }();

        if(length == sizeof(sockaddr_in6) && family == AF_INET6) {
            address_storage_ = sockaddr_in6{};
            std::memcpy(std::addressof(as6()), storage, sizeof(sockaddr_in6));
        } else if(length == sizeof(sockaddr_in) && family == AF_INET) {
            address_storage_ = sockaddr_in{};
            std::memcpy(std::addressof(as4()), storage, sizeof(sockaddr_in));
        } else if(length == sizeof(sockaddr_in6) && family == AF_INET) {
            address_storage_ = sockaddr_in{};
            std::memcpy(std::addressof(as4()), storage, sizeof(sockaddr_in));
        } else {
            TS_RAISE(std::runtime_error, "WTF unreachable??");
        }
    }

public:
    IPAddress() noexcept : address_storage_{defaultV4()} {}

    IPAddress(IPAddress const& addr, std::uint16_t port) : IPAddress{addr} {
        if(isIPv4()) {
            as4().sin_port = htons(port);
        } else if(isIPv6()) {
            as6().sin6_port = htons(port);
        } else {
            TS_RAISE(std::runtime_error, "WTF unreachable??");
        }
    }

    IPAddress(
      std::string const& host,
      std::uint16_t      port,
      Socket::Type       sockettype,
      Socket::Protocol   protocol,
      IP::Type           type)
      : IPAddress() {
        auto const addresses = resolve(host, port, sockettype, protocol, type);
        if(addresses.empty()) {
            TS_RAISE(std::runtime_error, "IPAddress failed: no host resolved");
        }
        address_storage_ = addresses.front().address_storage_;
    }

    friend bool operator==(IPAddress const& lhs, IPAddress const& rhs) {
        // TODO should ipv4 mapped ipv6 and ipv6 be considered equal???
        if(lhs.isIPv4() != rhs.isIPv4()) {
            return false;
        }

        if(lhs.get_port() != rhs.get_port()) {
            return false;
        }

        if(lhs.isIPv4()) {
            if(lhs.as4().sin_addr.s_addr != rhs.as4().sin_addr.s_addr) {
                return false;
            }
        } else {
            if(
              std::memcmp(
                std::addressof(lhs.as6().sin6_addr),
                std::addressof(rhs.as6().sin6_addr),
                sizeof(lhs.as6().sin6_addr))
              != 0)
            {
                return false;
            }
        }

        return true;
    }

    friend bool operator!=(IPAddress const& lhs, IPAddress const& rhs) { return !(lhs == rhs); }

    static IPAddress makeMulticast(std::string const& addr_str) {
        return makeMulticast_(addr_str, {});
    }

    static IPAddress makeMulticast(std::string const& addr_str, std::uint16_t port) {
        return makeMulticast_(addr_str, port);
    }

    static bool is_ephemeral_port(std::uint16_t port) noexcept {
        std::uint16_t minEphemeralPort = 32768;
        std::uint16_t maxEphemeralPort = 60999;
        return std::clamp(port, minEphemeralPort, maxEphemeralPort) != port;
    }

    bool is_loopback() const {
        if(isIPv4()) {
            if(as4().sin_addr.s_addr == ::htonl(INADDR_LOOPBACK)) {
                return true;
            }
        } else {
            in6_addr const loopback = IN6ADDR_LOOPBACK_INIT;
            if(
              std::memcmp(
                std::addressof(as6().sin6_addr),
                std::addressof(loopback),
                sizeof(loopback))
              == 0)
            {
                return true;
            }
        }
        return false;
    }

    bool isIPv4() const { return std::holds_alternative<sockaddr_in>(address_storage_); }
    bool isIPv6() const { return std::holds_alternative<sockaddr_in6>(address_storage_); }

    std::string get_ip() const {
        auto addr = [this]() -> void const* {
            if(isIPv4()) {
                return std::addressof(as4().sin_addr);
            }
            return std::addressof(as6().sin6_addr);
        }();

        static_assert(INET6_ADDRSTRLEN >= INET_ADDRSTRLEN, "strange ADDRSTRLEN");
        std::array<char, INET6_ADDRSTRLEN + 1> ipStr{};
        if(nullptr == ::inet_ntop(address_familie(), addr, ipStr.data(), ipStr.size() - 1)) {
            TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("inet_ntop failed");
            return "unknown";
        }
        ipStr.back() = '\0';
        return ipStr.data();
    }

    std::uint16_t get_port() const {
        if(isIPv4()) {
            return ntohs(as4().sin_port);
        }
        return ntohs(as6().sin6_port);
    }

    friend inline std::string to_string(IPAddress const& addr) { return addr.to_string(false); }

    std::string to_string(bool resolve = false) const {
        std::string         name{};
        std::string         servicename{};
        std::uint16_t const port = get_port();
        if(resolve) {
#ifdef EAI_SYSTEM
            name.resize(NI_MAXHOST);
            if(port != 0) {
                servicename.resize(NI_MAXSERV);
            }

            int const status = ::getnameinfo(
              get_sockaddr_ptr(),
              size(),
              name.data(),
              static_cast<socklen_t>(name.size()),
              port != 0 ? servicename.data() : nullptr,
              port != 0 ? static_cast<socklen_t>(servicename.size()) : 0,
              0);
            if(status != 0) {
                if(status == EAI_SYSTEM) {
                    TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("getnameinfo failed");
                } else {
                    TS_RAISE_PRINT_ONLY(
                      std::system_error,
                      status,
                      GAI_Error_Category(),
                      "getnameinfo failed");
                }
                name        = "";
                servicename = "";
            }
#endif
        }

        std::string_view const nameSv{name.data()};
        std::string_view const serviceSv{servicename.data()};
        auto const             ip = get_ip();

        std::string ret;
        ret.reserve(64);
        ret += isIPv4() ? "IPv4 " : "IPv6 ";
        ret += ip;

        if(nameSv.size() != 0 && ip != nameSv && resolve) {
            ret += '(';
            ret += nameSv;
            ret += ')';
        }

        if(port != 0) {
            auto const portstring = std::to_string(static_cast<std::size_t>(get_port()));
            ret += " port ";
            ret += portstring;

            if(serviceSv.size() != 0 && portstring != serviceSv && resolve) {
                ret += '(';
                ret += serviceSv;
                ret += ')';
            }
        }

        return ret;
    }

    std::variant<std::array<std::byte, 4>, std::array<std::byte, 16>> as_Bytes() const {
        if(isIPv4()) {
            auto const&              v = as4();
            std::array<std::byte, 4> ret;
            static_assert(sizeof(ret) == sizeof(v.sin_addr));
            std::memcpy(ret.data(), std::addressof(v.sin_addr), ret.size());
            return ret;
        } else {
            auto const&               v = as6();
            std::array<std::byte, 16> ret;
            static_assert(sizeof(ret) == sizeof(v.sin6_addr));
            std::memcpy(ret.data(), std::addressof(v.sin6_addr), ret.size());
            return ret;
        }
    }

    static IPAddress
    from_Bytes(std::variant<std::array<std::byte, 4>, std::array<std::byte, 16>> bytes) {
        if(std::holds_alternative<std::array<std::byte, 4>>(bytes)) {
            IPAddress addr;
            addr.address_storage_ = defaultV4();
            auto&       v         = addr.as4();
            auto const& by        = std::get<std::array<std::byte, 4>>(bytes);
            static_assert(sizeof(v.sin_addr) == sizeof(by));
            std::memcpy(std::addressof(v.sin_addr), std::addressof(by), sizeof(v.sin_addr));
            return addr;
        } else {
            IPAddress addr;
            addr.address_storage_ = defaultV6();
            auto&       v         = addr.as6();
            auto const& by        = std::get<std::array<std::byte, 16>>(bytes);
            static_assert(sizeof(v.sin6_addr) == sizeof(by));
            std::memcpy(std::addressof(v.sin6_addr), std::addressof(by), sizeof(v.sin6_addr));
            return addr;
        }
    }

    template<typename Stream>
    friend Stream& operator<<(Stream& o, IPAddress const& addr) {
        o << addr.to_string(false);
        return o;
    }

    static std::vector<IPAddress> resolve(
      std::string const& host,
      std::uint16_t      port,
      Socket::Type       sockettype,
      Socket::Protocol   protocol,
      IP::Type           type) {
        addrinfo hint{};
        hint.ai_family   = type == IP::Type::Any  ? AF_UNSPEC
                         : type == IP::Type::IPv4 ? AF_INET
                                                  : AF_INET6;
        hint.ai_protocol = static_cast<int>(protocol);
        hint.ai_socktype = static_cast<int>(sockettype);
        hint.ai_flags    = hint.ai_family != AF_INET6 ? AI_ADDRCONFIG : AI_ADDRCONFIG | AI_V4MAPPED;
        hint.ai_flags |= AI_NUMERICSERV;

        auto const        portString = std::to_string(static_cast<std::size_t>(port));
        char const* const portPtr    = portString.c_str();

        addrinfo* addrinfoRes;
        auto      f = [&]() {
            return ts::detail::retry_on_return<2>(
              EAGAIN,
              getaddrinfo,
              host.c_str(),
              portPtr,
              std::addressof(hint),
              std::addressof(addrinfoRes));
        };

#ifdef EAI_SYSTEM
        int const status = ts::detail::retry_on_errno<2>(EAI_SYSTEM, EINTR, f);
        if(status == EAI_SYSTEM) {
            TS_RAISE_SYSTEM_ERROR("getaddrinfo failed");
        }
#else
        int const status = f();
#endif
        if(status != 0) {
            TS_RAISE(std::system_error, status, GAI_Error_Category(), "getaddrinfo failed");
        }

        auto deleter = ts::make_scope_guard(
          [&]() { freeaddrinfo(addrinfoRes); },
          ts::ScopeGuardCallPolicy::always);

        std::vector<IPAddress> resolvedAddresses{};
        for(addrinfo const* p = addrinfoRes; p != nullptr; p = p->ai_next) {
            if(p->ai_addr != nullptr) {
                if(
                  (p->ai_family == AF_INET && (type == IP::Type::Any || type == IP::Type::IPv4))
                  || (p->ai_family == AF_INET6 && (type == IP::Type::Any || type == IP::Type::IPv6)))
                {
                    resolvedAddresses.push_back(IPAddress{*p});
                }
            }
        }

        return resolvedAddresses;
    }

private:
    static IPAddress
    makeMulticast_(std::string const& addr_str, std::optional<std::uint16_t> port) {
        IPAddress ret{};
        in6_addr  addr6;
        in_addr   addr;

        if(1 == inet_pton(AF_INET, addr_str.c_str(), &addr)) {
            ret.address_storage_ = defaultV4();
            ret.as4().sin_addr   = addr;
            if(port) {
                ret.as4().sin_port = htons(*port);
            }
            return ret;
        } else if(1 == inet_pton(AF_INET6, addr_str.c_str(), &addr6)) {
            ret.address_storage_ = defaultV6();
            ret.as6().sin6_addr  = addr6;
            if(port) {
                ret.as6().sin6_port = htons(*port);
            }
            return ret;
        } else {
            TS_RAISE(std::runtime_error, "not a valid ipaddress");
        }
    }
};

}   // namespace ts
