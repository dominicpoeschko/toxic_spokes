#include "toxic_spokes/detail/Socket_Impl.hpp"

#include "toxic_spokes/detail/FileDescriptor.hpp"
#include "toxic_spokes/detail/IPAddress.hpp"
#include "toxic_spokes/detail/ScopeGuard.hpp"
#include "toxic_spokes/detail/raise.hpp"
#include "toxic_spokes/detail/system_call_helper.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <iterator>
#include <limits>
#include <net/if.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#ifdef __linux__
    #include <ifaddrs.h>
#endif

namespace ts { namespace detail {

    Socket_Impl::Socket_Impl(Socket::Type type, bool needShutdown)
      : recv_timeout_{std::chrono::nanoseconds::max()}
      , send_timeout_{std::chrono::nanoseconds::max()}
      , socketType_{type}
      , socketDomain_{Socket::Domain::INET}
      , socketProtocol_{Socket::Protocol::DEFAULT}
      , ipType_{default_ip_type}
      , needShutdown_{needShutdown}
      , is_lisening{false}
      , fail_flag_{std::make_unique<std::atomic<bool>>(false)} {}

    Socket_Impl::Socket_Impl(
      Socket::Domain   domain,
      Socket::Type     type,
      Socket::Protocol protocol,
      bool             needShutdown)
      : Socket_Impl(type, needShutdown) {
        create_(domain, type, protocol, false);
    }

    Socket_Impl::Socket_Impl(FileDescriptor fd, Socket::Type type, bool needShutdown)
      : Socket_Impl(type, needShutdown) {
        file_descriptor_ = std::move(fd);
        set_recv_timeout_(recv_timeout_);
        set_send_timeout_(send_timeout_);
    }

    Socket_Impl::~Socket_Impl() noexcept {
        if(is_valid()) {
            try {
                if(needShutdown_) {
                    shutdown();
                }
            } catch(std::exception const& e) {
                try {
                    TS_LOG(e.what());
                } catch(...) {
                }
            } catch(...) {
            }
        }
    }

    Socket_Impl::operator FileDescriptor::View() noexcept {
        return FileDescriptor::View{file_descriptor_};
    }

    Socket_Impl::operator const FileDescriptor::View() const noexcept {
        return FileDescriptor::View{file_descriptor_};
    }

    bool Socket_Impl::get_fail_flag() {
        if(fail_flag_) {
            return *fail_flag_;
        }
        return true;
    }
    void Socket_Impl::set_fail_flag() {
        if(fail_flag_) {
            *fail_flag_ = true;
        }
    }

    void Socket_Impl::join_multicast_group(Addr_t const& multicast_addr) {
        multicast_group_(multicast_addr, true);
    }

    void Socket_Impl::leave_multicast_group(Addr_t const& multicast_addr) {
        multicast_group_(multicast_addr, false);
    }

    Socket_Impl::Addr_t Socket_Impl::get_address() {
        auto IP{get_name_(false)};
        return Addr_t{IP.first, IP.second};
    }

    Socket_Impl::Addr_t Socket_Impl::get_peer_address() {
        auto IP{get_name_(true)};
        return Addr_t{IP.first, IP.second};
    }

    std::vector<Socket_Impl::Addr_t> Socket_Impl::get_bound_interface_addresses() {
        auto addresses = get_address_from_interfaces_();

        addresses.erase(
          std::remove_if(
            addresses.begin(),
            addresses.end(),
            [&](auto const& addr) {
                if(addr.is_loopback()) {
                    return true;
                }
                switch(ipType_) {
                case IPType::Any:
                    {
                        return false;
                    }
                case IPType::IPv4:
                    {
                        return addr.isIPv6();
                    }
                case IPType::IPv6:
                    {
                        return addr.isIPv4();
                    }
                }
                return false;
            }),
          addresses.end());

        return addresses;
    }

    FileDescriptor Socket_Impl::release_FD() noexcept { return std::move(file_descriptor_); }

    void Socket_Impl::create_connect_(
      Socket::Type               sockettype,
      Socket::Protocol           protocol,
      std::vector<Addr_t> const& partners,
      std::chrono::nanoseconds   timeout) {
        if(partners.empty()) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR_CE(EHOSTUNREACH, "connect failed");
        }
        std::vector<std::exception_ptr> eptrs;
        for(auto const& a : partners) {
            try {
                create_(Socket::Domain(a.address_familie()), sockettype, protocol, true);
                connect_IP_(a, timeout, true);
                return;
            } catch(...) {
                if(file_descriptor_.is_valid()) {
                    file_descriptor_.close();
                }
                eptrs.push_back(std::current_exception());
            }
        }

        set_fail_flag();

        if(eptrs.size() != partners.size()) {
            // unreachable???
            TS_RAISE_SYSTEM_ERROR_CE(EHOSTUNREACH, "connect failed");
        }

        for(std::size_t i{}; i < eptrs.size(); ++i) {
            auto& eptr = eptrs[i];
            if(eptr) {
                std::rethrow_exception(eptr);
        }
        }
        // unreachable???
        TS_RAISE_SYSTEM_ERROR_CE(EHOSTUNREACH, "connect failed");
    }

    std::size_t Socket_Impl::send(std::span<std::byte const> buffer) {
        return sendto_int_(nullptr, 0, buffer, 0, true);
    }
    std::size_t Socket_Impl::send_nonblocking(std::span<std::byte const> buffer) {
        return sendto_int_(nullptr, 0, buffer, MSG_DONTWAIT, false);
    }

    std::size_t Socket_Impl::sendto(Addr_t const& dst, std::span<std::byte const> buffer) {
        return sendto_int_(dst.get_sockaddr_ptr(), dst.size(), buffer, 0, false);
    }
    std::size_t
    Socket_Impl::sendto_nonblocking(Addr_t const& dst, std::span<std::byte const> buffer) {
        return sendto_int_(dst.get_sockaddr_ptr(), dst.size(), buffer, MSG_DONTWAIT, false);
    }

    std::size_t Socket_Impl::recv_int_(std::span<std::byte> buffer, int flags, bool useTimeout) {
        return recvfrom_int_(
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          buffer,
          flags,
          useTimeout);
    }

    std::size_t Socket_Impl::recv_nonblocking(std::span<std::byte> buffer) {
        return recv_int_(buffer, MSG_DONTWAIT, !Socket::is_packet_based_type(socketType_));
    }

    std::size_t Socket_Impl::peek_nonblocking(std::span<std::byte> buffer) {
        return recv_int_(
          buffer,
          MSG_PEEK | MSG_DONTWAIT,
          !Socket::is_packet_based_type(socketType_));
    }

    std::size_t Socket_Impl::recv(std::span<std::byte> buffer) {
        return recv_int_(buffer, MSG_WAITALL, !Socket::is_packet_based_type(socketType_));
    }

    std::size_t Socket_Impl::peek(std::span<std::byte> buffer) {
        return recv_int_(
          buffer,
          MSG_PEEK | MSG_WAITALL,
          !Socket::is_packet_based_type(socketType_));
    }

    std::size_t
    Socket_Impl::recvfrom_src_int_(Addr_t* src, std::span<std::byte> buffer, int flags) {
        if(src == nullptr) {
            return recv_int_(buffer, flags, false);
        }
        sockaddr_storage storage{};
        socklen_t        length{sizeof(storage)};
        auto const       s = recvfrom_int_(
          &storage,
          &length,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          buffer,
          flags,
          false);
        if(s != 0) {
            *src = Addr_t{storage, length};
        }
        return s;
    }

    std::size_t Socket_Impl::recvfrom_src_dst_int_(
      Addr_t*              src,
      Addr_t*              dst,
      std::span<std::byte> buffer,
      int                  flags) {
        if(src == nullptr && dst == nullptr) {
            return recv_int_(buffer, flags, false);
        }
        if(dst == nullptr) {
            return recvfrom_src_int_(src, buffer, flags);
        }

        sockaddr_storage src_storage{};
        socklen_t        src_length{sizeof(src_storage)};
        sockaddr_storage dst_storage{};
        socklen_t        dst_length{sizeof(dst_storage)};
        auto const       s = recvfrom_int_(
          &src_storage,
          &src_length,
          &dst_storage,
          &dst_length,
          nullptr,
          nullptr,
          buffer,
          flags,
          false);
        if(s != 0) {
            *src = Addr_t{src_storage, src_length};
            *dst = Addr_t{dst_storage, dst_length};
        }
        return s;
    }

    std::size_t Socket_Impl::recvfrom_src_dst_ifa_int_(
      Addr_t*              src,
      Addr_t*              dst,
      Addr_t*              ifa,
      std::span<std::byte> buffer,
      int                  flags) {
        if(src == nullptr && dst == nullptr && ifa == nullptr) {
            return recv_int_(buffer, flags, false);
        }
        if(dst == nullptr && ifa == nullptr) {
            return recvfrom_src_int_(src, buffer, flags);
        }
        if(ifa == nullptr) {
            return recvfrom_src_dst_int_(src, dst, buffer, flags);
        }
        if(dst == nullptr) {
            TS_RAISE(std::runtime_error, "ifa without dst not possible");
        }

        sockaddr_storage src_storage{};
        socklen_t        src_length{sizeof(src_storage)};
        sockaddr_storage dst_storage{};
        socklen_t        dst_length{sizeof(dst_storage)};
        sockaddr_storage ifa_storage{};
        socklen_t        ifa_length{sizeof(ifa_storage)};
        auto const       s = recvfrom_int_(
          &src_storage,
          &src_length,
          &dst_storage,
          &dst_length,
          &ifa_storage,
          &ifa_length,
          buffer,
          flags,
          false);
        if(s != 0) {
            *src = Addr_t{src_storage, src_length};
            *dst = Addr_t{dst_storage, dst_length};
            *ifa = Addr_t{ifa_storage, ifa_length};
        }
        return s;
    }

    std::size_t Socket_Impl::recvfrom(Addr_t* src, std::span<std::byte> buffer) {
        return recvfrom_src_int_(src, buffer, MSG_WAITALL);
    }

    std::size_t Socket_Impl::recvfrom(Addr_t* src, Addr_t* dst, std::span<std::byte> buffer) {
        return recvfrom_src_dst_int_(src, dst, buffer, MSG_WAITALL);
    }
    std::size_t
    Socket_Impl::recvfrom(Addr_t* src, Addr_t* dst, Addr_t* ifa, std::span<std::byte> buffer) {
        return recvfrom_src_dst_ifa_int_(src, dst, ifa, buffer, MSG_WAITALL);
    }

    std::size_t Socket_Impl::recvfrom_nonblocking(Addr_t* src, std::span<std::byte> buffer) {
        return recvfrom_src_int_(src, buffer, MSG_DONTWAIT);
    }

    std::size_t Socket_Impl::peekfrom(Addr_t* src, std::span<std::byte> buffer) {
        return recvfrom_src_int_(src, buffer, MSG_PEEK | MSG_WAITALL);
    }
    std::size_t Socket_Impl::peekfrom(Addr_t* src, Addr_t* dst, std::span<std::byte> buffer) {
        return recvfrom_src_dst_int_(src, dst, buffer, MSG_PEEK | MSG_WAITALL);
    }
    std::size_t
    Socket_Impl::peekfrom(Addr_t* src, Addr_t* dst, Addr_t* ifa, std::span<std::byte> buffer) {
        return recvfrom_src_dst_ifa_int_(src, dst, ifa, buffer, MSG_PEEK | MSG_WAITALL);
    }

    std::size_t Socket_Impl::peekfrom_nonblocking(Addr_t* src, std::span<std::byte> buffer) {
        return recvfrom_src_int_(src, buffer, MSG_PEEK | MSG_DONTWAIT);
    }

    void Socket_Impl::set_recv_timeout_(std::chrono::nanoseconds timeout) {
        recv_timeout_ = chrono::clamp_to_positive(timeout);
        set_timeout_(timeout, SO_RCVTIMEO);
    }

    void Socket_Impl::set_send_timeout_(std::chrono::nanoseconds timeout) {
        send_timeout_ = chrono::clamp_to_positive(timeout);
        set_timeout_(timeout, SO_SNDTIMEO);
    }

    void Socket_Impl::handle_self_connect_(Addr_t const& partner) {
        auto const partnerPort = partner.get_port();
        auto const isEphemeral = Addr_t::is_ephemeral_port(partnerPort);
        auto const isLoopback  = partner.is_loopback();
        if(isEphemeral && isLoopback) {
            auto const a = get_address();
            auto const p = get_peer_address();
            if(a != p) {
                return;
            }
            TS_LOG("Detected self connect shutdown now!");
            try {
                shutdown();
            } catch(...) {
            }
            TS_RAISE_SYSTEM_ERROR_CE(EDEADLK, "connect failed");
        }
    }

    std::size_t Socket_Impl::bytes_available() {
        int bytesAv = 0;
        if(-1 == ::ioctl(file_descriptor_.fd(), FIONREAD, std::addressof(bytesAv))) {
            TS_RAISE_SYSTEM_ERROR("ioctl(FIONREAD) failed");
        }
        if(0 > bytesAv) {
            TS_RAISE_SYSTEM_ERROR_CE(ERANGE, "ioctl(FIONREAD) failed");
        }
        return static_cast<std::size_t>(bytesAv);
    }

    bool Socket_Impl::is_valid() noexcept {
        if(!file_descriptor_.is_valid()) {
            return false;
        }

        if(get_fail_flag()) {
            return false;
        }

        int       errorcode{};
        socklen_t length{sizeof(errorcode)};
        if(
          0
          != ::getsockopt(
            file_descriptor_.fd(),
            SOL_SOCKET,
            SO_ERROR,
            std::addressof(errorcode),
            std::addressof(length)))
        {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("getsockopt(SO_ERROR) failed");
            return false;
        }
        if(errorcode != 0) {
            set_fail_flag();
            // do not print since this is pretty common
            //TS_RAISE_SYSTEM_ERROR_CE_PRINT_ONLY(errorcode, "getsockopt(SO_ERROR) outparam failed");
            return false;
        }

        if(is_lisening) {
            return true;
        }

        std::uint8_t data;
        auto const   ret = ::recv(
          file_descriptor_.fd(),
          std::addressof(data),
          sizeof(data),
          MSG_PEEK | MSG_DONTWAIT);

        if(ret == 0) {
            set_fail_flag();
            // do not print since this is pretty common
            //TS_RAISE_SYSTEM_ERROR_CE_PRINT_ONLY(ECONNRESET, "recv in is_valid failed");
            return false;
        }

        if(-1 == ret && !is_errno_recoverable(errno)) {
            // TODO check if recv is shutdown

            set_fail_flag();
            // do not print since this is pretty common
            //TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("recv in is_valid failed");
            return false;
        }

        return true;
    }

    void Socket_Impl::shutdown_recv() {
        if(-1 == ::shutdown(file_descriptor_.fd(), SHUT_RD)) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("shutdown recv failed");
        }
    }
    void Socket_Impl::shutdown_send() {
        if(-1 == ::shutdown(file_descriptor_.fd(), SHUT_WR)) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("shutdown send failed");
        }
    }
    void Socket_Impl::shutdown() {
        if(-1 == ::shutdown(file_descriptor_.fd(), SHUT_RDWR)) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("shutdown failed");
        }
    }

    void Socket_Impl::set_timeout_(std::chrono::nanoseconds timeout, int opname) {
        timeval const tv = chrono::to_timeval(timeout);

        if(
          -1
          == ::setsockopt(
            file_descriptor_.fd(),
            SOL_SOCKET,
            opname,
            std::addressof(tv),
            sizeof(struct timeval)))
        {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("setsockopt failed");
        }
    }

    void Socket_Impl::enable_broadcast(bool enable) {
        int const       enableInt = enable ? 1 : 0;
        socklen_t const length{sizeof(enableInt)};
        if(
          -1
          == ::setsockopt(
            file_descriptor_.fd(),
            SOL_SOCKET,
            SO_BROADCAST,
            std::addressof(enableInt),
            length))
        {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("setsockopt(SO_BROADCAST) failed");
        }
    }

    void Socket_Impl::multicast_group_(Addr_t const& multicast_addr, bool join) {
        void*     addr{};
        socklen_t len{};
        int       protocol{};
        int       optname{};
        ip_mreq   req4{};
        ipv6_mreq req6{};

        std::uint8_t netif_index =
#ifdef __linux__
          0
#else
          2
#endif
          ;

        if(multicast_addr.isIPv4()) {
            req4.imr_multiaddr        = multicast_addr.as4().sin_addr;
            req4.imr_interface.s_addr = INADDR_ANY;
            len                       = sizeof(req4);
            addr                      = std::addressof(req4);
            protocol                  = IPPROTO_IP;
            optname                   = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
        } else {
            req6.ipv6mr_multiaddr = multicast_addr.as6().sin6_addr;
            req6.ipv6mr_interface = netif_index;
            len                   = sizeof(req6);
            addr                  = std::addressof(req6);
            protocol              = IPPROTO_IPV6;
            optname               = join ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP;
        }

        if(-1 == ::setsockopt(file_descriptor_.fd(), protocol, optname, addr, len)) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR(
              std::string("setsockopt(") + (join ? "IP_ADD_MEMBERSHIP" : "IP_DROP_MEMBERSHIP")
              + ") failed");
        }
    }

    void Socket_Impl::multicast_loop(bool enable) {
        auto set = [&](auto protocol, auto optname) {
            int v = enable ? 1 : 0;
            if(
              -1
              == ::setsockopt(
                file_descriptor_.fd(),
                protocol,
                optname,
                std::addressof(v),
                sizeof(v))) {
                set_fail_flag();
                TS_RAISE_SYSTEM_ERROR("setsockopt(IP_MULTICAST_LOOP) failed");
            }
        };

        if(socketDomain_ == Socket::Domain::INET6) {
            set(IPPROTO_IP, IP_MULTICAST_LOOP);
            set(IPPROTO_IPV6, IPV6_MULTICAST_LOOP);
        } else {
            set(IPPROTO_IP, IP_MULTICAST_LOOP);
        }
    }

    void Socket_Impl::listen(std::size_t max_connections) {
        is_lisening = true;
        if(
          -1
          == ::listen(
            file_descriptor_.fd(),
            static_cast<int>(std::clamp<std::size_t>(max_connections, 0, SOMAXCONN))))
        {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("listen failed");
        }
    }

    std::pair<sockaddr_storage, socklen_t> Socket_Impl::get_name_(bool peer) {
        sockaddr_storage s{};
        socklen_t        size = sizeof(s);

        if(peer) {
            if(
              -1
              == ::getpeername(
                file_descriptor_.fd(),
                Addr_t::to_sockaddr(std::addressof(s)),
                std::addressof(size)))
            {
                TS_RAISE_SYSTEM_ERROR("getpeername failed");
            }

        } else {
            if(
              -1
              == ::getsockname(
                file_descriptor_.fd(),
                Addr_t::to_sockaddr(std::addressof(s)),
                std::addressof(size)))
            {
                TS_RAISE_SYSTEM_ERROR("getsockname failed");
            }
        }

        return {s, size};
    }

    std::size_t Socket_Impl::sendto_int_(
      sockaddr const*            dst,
      socklen_t                  length,
      std::span<std::byte const> buffer,
      int                        flags,
      bool                       useTimeout) {
        std::size_t size = buffer.size();
        if(size == 0) {
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "sendto failed");
        }

        auto const oldSendTimeout = send_timeout_;
        auto const stoptime
          = useTimeout ? chrono::calc_stop_time<Clock>(oldSendTimeout) : Clock::time_point{};
        auto guard = make_scope_guard(
          [this, oldSendTimeout]() { set_send_timeout_(oldSendTimeout); },
          ScopeGuardCallPolicy::never);

        auto handleTimeout = [&]() {
            if(!useTimeout) {
                return false;
            }
            auto const now = Clock::now();
            if(now >= stoptime) {
                return false;
            }
            guard.setPolicy(ScopeGuardCallPolicy::always);
            set_send_timeout_(stoptime - now);
            return true;
        };

        std::size_t bytesSend{};
        while(true) {
            ssize_t const status = ::sendto(
              file_descriptor_.fd(),
              detail::next(buffer.data(), bytesSend),
              size - bytesSend,
              flags | MSG_NOSIGNAL,
              dst,
              length);

            if(status == 0) {
                set_fail_flag();
                // can this even happen? and when yes is it an error?
                TS_RAISE_SYSTEM_ERROR_CE(ECONNRESET, "sendto failed");
            }
            if(status == -1) {
                if(is_errno_recoverable(errno)) {
                    if(!detail::isflagSet(flags, MSG_DONTWAIT)) {
                        if(handleTimeout()) {
                            continue;
                        }
                        TS_RAISE(
                          Com_Transmit_Exception,
                          Com_Transmit_Exception::Type::send_timeout,
                          bytesSend,
                          "sendto timeout");
                    }
                    return bytesSend;
                }
                set_fail_flag();
                TS_RAISE_SYSTEM_ERROR("sendto failed");
            }

            bytesSend += static_cast<std::size_t>(status);

            if(bytesSend != size && useTimeout) {
                if(!detail::isflagSet(flags, MSG_DONTWAIT)) {
                    if(handleTimeout()) {
                        continue;
                    }
                    TS_RAISE(
                      Com_Transmit_Exception,
                      Com_Transmit_Exception::Type::send_timeout,
                      bytesSend,
                      "sendto timeout");
                }
            }
            return bytesSend;
        }
    }
    std::vector<Socket_Impl::Addr_t> Socket_Impl::get_address_from_interfaces_() {
        std::vector<Socket_Impl::Addr_t> ret;

#ifdef __linux__
        ifaddrs* ifas;
        if(-1 == ::getifaddrs(&ifas)) {
            TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("getifaddrs failed");
            return {};
        }
        std::unique_ptr<ifaddrs, decltype(std::addressof(::freeifaddrs))> ifasUp(
          ifas,
          ::freeifaddrs);

        auto getLength
          = [](auto fam) { return fam == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6); };

        for(ifaddrs const* it = ifas; it != nullptr; it = it->ifa_next) {
            if(it->ifa_addr != nullptr) {
                if(it->ifa_addr->sa_family == AF_INET6 || it->ifa_addr->sa_family == AF_INET) {
                    ret.push_back(Addr_t(
                      *it->ifa_addr,
                      static_cast<socklen_t>(getLength(it->ifa_addr->sa_family))));
                }
            }
        }
#endif
        return ret;
    }

    bool Socket_Impl::get_address_from_interface_index_(
      int               if_index,
      int               family,
      sockaddr_storage* ifa,
      socklen_t*        ifa_length) {
#ifdef __linux__
        ifreq ifr;
        ifr.ifr_ifindex = if_index;
        if(-1 == ::ioctl(file_descriptor_.fd(), SIOCGIFNAME, &ifr)) {
            TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("ioctl(SIOCGIFNAME) failed");
            return false;
        } else {
            ifaddrs* ifas;
            if(-1 == ::getifaddrs(&ifas)) {
                TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("getifaddrs failed");
                return false;
            }
            std::unique_ptr<ifaddrs, decltype(std::addressof(::freeifaddrs))> ifasUp(
              ifas,
              ::freeifaddrs);

            std::vector<sockaddr const*> addrs;

            for(ifaddrs const* it = ifas; it != nullptr; it = it->ifa_next) {
                if(
                  0 == std::strcmp(it->ifa_name, ifr.ifr_ifrn.ifrn_name) && it->ifa_addr != nullptr)
                {
                    if(it->ifa_addr->sa_family == AF_INET6 || it->ifa_addr->sa_family == AF_INET) {
                        addrs.push_back(it->ifa_addr);
                    }
                }
            }

            auto getLength = [](auto fam) {
                return fam == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            };

            if(!addrs.empty()) {
                std::sort(begin(addrs), end(addrs), [&](auto a1, auto a2) {
                    if(a1->sa_family == a2->sa_family) {
                        return false;
                    }
                    if(a1->sa_family == family) {
                        return true;
                    }
                    if(a2->sa_family == family) {
                        return false;
                    }
                    if(a1->sa_family == AF_INET6) {
                        return true;
                    }
                    if(a2->sa_family == AF_INET6) {
                        return false;
                    }
                    return false;
                });

                sockaddr const* cpy    = addrs.front();
                socklen_t       length = static_cast<socklen_t>(getLength(cpy->sa_family));
                if(length > *ifa_length) {
                    TS_RAISE_PRINT_ONLY(std::runtime_error, "length wrong");
                    return false;
                }
                *ifa_length = length;

                std::memcpy(ifa, cpy, length);
                return true;
            }
        }
        return false;
#else
        netif const* netif = netif_get_by_index(if_index);
        if(netif == nullptr) {
            TS_RAISE_PRINT_ONLY(std::runtime_error, "netif_get_by_index failed");
            return false;
        }
        if(netif->ip_addr.type == IPADDR_TYPE_V4) {
            ifa->s2_len      = sizeof(sockaddr_in);
            ifa->ss_family   = AF_INET;
            ifa->s2_data1[0] = 0;
            ifa->s2_data1[1] = 0;
            ifa->s2_data2[0] = netif->ip_addr.u_addr.ip4.addr;
            ifa->s2_data2[1] = 0;
            ifa->s2_data2[2] = 0;
            *ifa_length      = sizeof(sockaddr_in);
            return true;
        } else if(netif->ip_addr.type == IPADDR_TYPE_V6) {
            /*    ifa->s2_len      = sizeof(sockaddr_in6);
            ifa->ss_family   = AF_INET6;
            ifa->s2_data1[0] = 0;
            ifa->s2_data1[1] = 0;
            ifa->s2_data2[0] = netif->ip_addr.u_addr.ip4.addr;
            ifa->s2_data2[1] = 0;
            ifa->s2_data2[2] = 0;
            *ifa_length      = sizeof(sockaddr_in6);*/
            TS_RAISE_PRINT_ONLY(std::runtime_error, "netif_get_by_index no IPV6");
            return false;
        }

        TS_RAISE_PRINT_ONLY(std::runtime_error, "netif_get_by_index no ip?");
        return false;
#endif
    }

    std::size_t Socket_Impl::recvfrom_int_(
      sockaddr_storage*    src,
      socklen_t*           src_length,
      sockaddr_storage*    dst,
      socklen_t*           dst_length,
      sockaddr_storage*    ifa,
      socklen_t*           ifa_length,
      std::span<std::byte> buffer,
      int                  flags,
      bool                 useTimeout) {
        std::size_t size = buffer.size();
        if(size == 0) {
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "recvfrom failed");
        }

        auto const oldRecvTimeout = recv_timeout_;
        auto const stoptime
          = useTimeout ? chrono::calc_stop_time<Clock>(oldRecvTimeout) : Clock::time_point{};
        auto guard = make_scope_guard(
          [this, oldRecvTimeout]() { set_recv_timeout_(oldRecvTimeout); },
          ScopeGuardCallPolicy::never);

        auto handleTimeout = [&]() {
            if(!useTimeout) {
                return false;
            }
            auto const now = Clock::now();
            if(now >= stoptime) {
                return false;
            }
            guard.setPolicy(ScopeGuardCallPolicy::always);
            set_recv_timeout_(stoptime - now);
            return true;
        };

        auto make_address = [](sockaddr_storage* addr, socklen_t* lenght, bool maybe_valid) {
            if(addr && maybe_valid) {
                if(*lenght != 0) {
                    return std::optional<Addr_t>{
                      Addr_t{*addr, *lenght}
                    };
                }
            }
            return std::optional<Addr_t>{};
        };

        if(Socket::is_packet_based_type(socketType_)) {
            flags |= MSG_TRUNC;
        }

        std::size_t bytesReceived{};

        auto throw_com_error = [&](auto type, auto const& msg) {
            bool maybe_valid = bytesReceived != 0;
            TS_RAISE(
              Com_Transmit_Exception,
              type,
              bytesReceived,
              msg,
              make_address(src, src_length, maybe_valid),
              make_address(dst, dst_length, maybe_valid),
              make_address(ifa, ifa_length, maybe_valid));
        };

        while(true) {
            ssize_t const status = [&]() {
                if(dst == nullptr) {
                    if(ifa != nullptr) {
                        TS_RAISE(std::runtime_error, "ifa without dst not possible");
                    }
                    return ::recvfrom(
                      file_descriptor_.fd(),
                      detail::next(buffer.data(), bytesReceived),
                      size - bytesReceived,
                      flags,
                      reinterpret_cast<sockaddr*>(src),
                      src_length);
                } else {
                    std::array<
                      char,
#ifdef IPV6_PKTINFO
                      sizeof(in6_pktinfo)
#else
                      sizeof(in_pktinfo)
#endif
                        + sizeof(cmsghdr)>
                          info_buffer;
                    iovec vec;
                    vec.iov_base = detail::next(buffer.data(), bytesReceived);
                    vec.iov_len  = size - bytesReceived;

                    msghdr hdr;
                    hdr.msg_name       = src;
                    hdr.msg_namelen    = src_length != nullptr ? *src_length : 0;
                    hdr.msg_iov        = &vec;
                    hdr.msg_iovlen     = 1;
                    hdr.msg_control    = info_buffer.data();
                    hdr.msg_controllen = info_buffer.size();

                    int flagstouse = flags;
                    if(Socket::is_packet_based_type(socketType_)) {
                        flagstouse = detail::clearflag(flags, MSG_WAITALL);
                        flagstouse = detail::clearflag(flagstouse, MSG_TRUNC);
                    }

                    auto const tmp_status = ::recvmsg(file_descriptor_.fd(), &hdr, flagstouse);
                    if(tmp_status > 0) {
                        if(src_length != nullptr) {
                            *src_length = hdr.msg_namelen;
                        }
                        cmsghdr* cmsgptr{};
                        bool     addrOk   = false;
                        bool     ifaddrOk = false;
                        for(cmsgptr = CMSG_FIRSTHDR(&hdr); cmsgptr != nullptr;
                            cmsgptr = CMSG_NXTHDR(&hdr, cmsgptr)) {
                            int if_index{};
                            int family{};
                            if(
                              cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_PKTINFO)
                            {
                                in_pktinfo const* ptr
                                  = reinterpret_cast<in_pktinfo const*>(CMSG_DATA(cmsgptr));
                                sockaddr_in addr = Addr_t::defaultV4();
                                addr.sin_addr    = ptr->ipi_addr;
                                std::memcpy(dst, &(addr), sizeof(addr));
                                *dst_length = sizeof(addr);
                                addrOk      = true;
                                family      = AF_INET;
                                if_index    = ptr->ipi_ifindex;
                            }
#ifdef IPV6_PKTINFO
                            else if(
                              cmsgptr->cmsg_level == IPPROTO_IPV6
                              && cmsgptr->cmsg_type == IPV6_PKTINFO)
                            {
                                in6_pktinfo const* ptr
                                  = reinterpret_cast<in6_pktinfo const*>(CMSG_DATA(cmsgptr));
                                sockaddr_in6 addr6 = Addr_t::defaultV6();
                                addr6.sin6_addr    = ptr->ipi6_addr;
                                std::memcpy(dst, &(addr6), sizeof(addr6));
                                *dst_length = sizeof(addr6);
                                addrOk      = true;
                                family      = AF_INET6;
                                if_index    = static_cast<int>(ptr->ipi6_ifindex);
                            }
#endif
                            if(addrOk) {
                                if(ifa != nullptr && ifa_length != nullptr) {
                                    ifaddrOk = get_address_from_interface_index_(
                                      if_index,
                                      family,
                                      ifa,
                                      ifa_length);
                                } else {
                                    ifaddrOk = true;
                                }
                                break;
                            }
                        }
                        if(!addrOk || !ifaddrOk) {
                            TS_RAISE(
                              Com_Transmit_Exception,
                              Com_Transmit_Exception::Type::address_error,
                              bytesReceived + static_cast<std::size_t>(tmp_status),
                              "address failed",
                              make_address(src, src_length, true),
                              make_address(dst, dst_length, addrOk),
                              make_address(ifa, ifa_length, ifaddrOk));
                        }
                    }
                    return tmp_status;
                }
            }();

            if(status == 0) {
                set_fail_flag();
                if(bytesReceived != 0) {
                    throw_com_error(
                      Com_Transmit_Exception::Type::socket_failed,
                      "recvfrom failed socket_shutdown");
                }
                TS_RAISE_SYSTEM_ERROR_CE(ECONNRESET, "recvfrom failed");
            }
            if(status == -1) {
                if(is_errno_recoverable(errno)) {
                    if(!detail::isflagSet(flags, MSG_DONTWAIT)) {
                        if(handleTimeout()) {
                            continue;
                        }
                        throw_com_error(
                          Com_Transmit_Exception::Type::recv_timeout,
                          "recvfrom timeout");
                    }
                    return bytesReceived;
                }
                set_fail_flag();
                if(bytesReceived != 0) {
                    TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("recvfrom failed");
                    throw_com_error(
                      Com_Transmit_Exception::Type::socket_failed,
                      "recvfrom failed socket_failed");
                }

                TS_RAISE_SYSTEM_ERROR("recvfrom failed");
            }

            bytesReceived += static_cast<std::size_t>(status);

            if(bytesReceived != size) {
                if(detail::isflagSet(flags, MSG_TRUNC)) {
                    if(bytesReceived > size) {
                        throw_com_error(
                          Com_Transmit_Exception::Type::buffer_to_small_for_packet,
                          "recvfrom got datagram with to small buffer");
                    }
                    // OK got datagram which was smaller then the buffer
                } else if(useTimeout) {
                    if(!detail::isflagSet(flags, MSG_DONTWAIT)) {
                        if(handleTimeout()) {
                            if(detail::isflagSet(flags, MSG_PEEK)) {
                                bytesReceived = 0;
                            }
                            continue;
                        }
                        throw_com_error(
                          Com_Transmit_Exception::Type::recv_timeout,
                          "recvfrom timeout");
                    }
                }
            }
            return bytesReceived;
        }
    }

    void Socket_Impl::enable_pktinfo_() {
        bool const v6 = socketDomain_ == Socket::Domain::INET6;

#ifndef IPV6_RECVPKTINFO
        int const pkinfov6 = 0;
        int const protov6  = 0;
        if(v6) {
            set_fail_flag();
            TS_RAISE(std::runtime_error, "IPV6 UDP RECVPKTINFO not supported");
        }
#else
        int const pkinfov6 = IPV6_RECVPKTINFO;
        int const protov6  = IPPROTO_IPV6;
#endif

        int const type = v6 ? protov6 : IPPROTO_IP;
        int const opt  = v6 ? pkinfov6 : IP_PKTINFO;

        int const on = 1;
        if(-1 == ::setsockopt(file_descriptor_.fd(), type, opt, std::addressof(on), sizeof(on))) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("setsockopt(IP_PKTINFO) failed");
        }
    }
    void Socket_Impl::create_(
      Socket::Domain   domain,
      Socket::Type     type,
      Socket::Protocol protocol,
      bool             silent) {
        // do not reassign directly since the possible close call could override errno
        int const new_fd = ::socket(
          static_cast<int>(domain),
          static_cast<int>(type)
#ifdef SOCK_CLOEXEC
            | SOCK_CLOEXEC
#endif
          ,
          static_cast<int>(protocol));
        if(new_fd == -1) {
            TS_RAISE_SYSTEM_ERROR_MAYBE_SILENT(silent, "socket failed");
        }
        socketType_     = type;
        socketProtocol_ = protocol;
        socketDomain_   = domain;
        file_descriptor_.reassign(new_fd);
    }

    void Socket_Impl::connect_(
      sockaddr const*          address,
      socklen_t                length,
      std::chrono::nanoseconds timeout,
      bool                     silent) {
        auto const stoptime = Clock::now() + timeout;
        int const  oldArg   = ::fcntl(file_descriptor_.fd(), F_GETFL, nullptr);
        if(oldArg < 0) {
            TS_RAISE_SYSTEM_ERROR_MAYBE_SILENT(silent, "fcntl get failed");
        }

        if(-1 == ::fcntl(file_descriptor_.fd(), F_SETFL, oldArg | O_NONBLOCK)) {
            TS_RAISE_SYSTEM_ERROR_MAYBE_SILENT(silent, "fcntl set failed");
        }

        auto const guard = make_scope_guard(
          [this, oldArg, silent]() {
              if(-1 == ::fcntl(file_descriptor_.fd(), F_SETFL, oldArg)) {
                  TS_RAISE_SYSTEM_ERROR_MAYBE_SILENT(silent, "fcntl set failed");
              }
          },
          ScopeGuardCallPolicy::always);

        while(true) {
            if(-1 == ::connect(file_descriptor_.fd(), address, length)) {
                auto errnoCopy = errno;
                if(errnoCopy != EINTR) {
                    if(errnoCopy == EINPROGRESS) {
                        if(file_descriptor_.can_send(timeout)) {
                            int       so_error;
                            socklen_t len = sizeof(so_error);

                            if(
                              0
                              != getsockopt(
                                file_descriptor_.fd(),
                                SOL_SOCKET,
                                SO_ERROR,
                                &so_error,
                                &len)) {
                                TS_RAISE_SYSTEM_ERROR_MAYBE_SILENT(silent, "getsockopt failed");
                            }

                            if(so_error == 0) {
                                return;
                            } else {
                                TS_RAISE_SYSTEM_ERROR_CE_MAYBE_SILENT(
                                  silent,
                                  so_error,
                                  "connect failed");
                            }
                        } else {
                            TS_RAISE_SYSTEM_ERROR_CE_MAYBE_SILENT(
                              silent,
                              ETIMEDOUT,
                              "connect timeout");
                        }
                    } else {
                        TS_RAISE_SYSTEM_ERROR_CE_MAYBE_SILENT(silent, errnoCopy, "connect failed");
                    }
                }

                auto const now = Clock::now();
                if(now >= stoptime) {
                    TS_RAISE_SYSTEM_ERROR_CE_MAYBE_SILENT(silent, ETIMEDOUT, "connect timeout");
                }
                timeout = stoptime - now;
            } else {
                return;
            }
        }
    }
    void
    Socket_Impl::connect_IP_(Addr_t const& partner, std::chrono::nanoseconds timeout, bool silent) {
        ipType_ = partner.isIPv4() ? IP::Type::IPv4 : IP::Type::IPv6;
        connect_(partner.get_sockaddr_ptr(), partner.size(), timeout, silent);
        handle_self_connect_(partner);
    }

#ifdef PF_UNIX
    void Socket_Impl::connect_UNIX_(
      std::pair<sockaddr_un, socklen_t> const& address,
      std::chrono::nanoseconds                 timeout) {
        connect_(
          reinterpret_cast<sockaddr const*>(std::addressof(address.first)),
          address.second,
          timeout,
          false);
    }

    std::string Socket_Impl::get_file_name_(bool peer) {
        auto        name{get_name_(peer)};
        sockaddr_un addr{};
        std::memcpy(std::addressof(addr), std::addressof(name.first), sizeof(sockaddr_un));

        if(sizeof(sa_family_t) > static_cast<std::size_t>(name.second)) {
            TS_RAISE(std::runtime_error, "WTF unreachable??");
        }
        if(static_cast<std::size_t>(name.second) > sizeof(sockaddr_un)) {
            TS_RAISE(std::runtime_error, "WTF unreachable??");
        }
        std::string s{
          std::begin(addr.sun_path),
          detail::next(std::begin(addr.sun_path), name.second - sizeof(sa_family_t))};

        if(addr.sun_path[0] == '\0') {
            std::transform(begin(s), end(s), begin(s), [](char c) {
                if(c == '\0') {
                    return '@';
                }
                return c;
            });
        }
        return s;
    }
    std::string Socket_Impl::get_peer_file_name() { return get_file_name_(true); }

    std::string Socket_Impl::get_file_name() { return get_file_name_(false); }

#endif

    void Socket_Impl::bind_IP(std::uint16_t port, IP::Type type, bool reuse_addr, bool reuse_port) {
        ipType_ = type;

        if(reuse_addr) {
            int const on = 1;
            if(
              -1
              == ::setsockopt(
                file_descriptor_.fd(),
                SOL_SOCKET,
                SO_REUSEADDR,
                std::addressof(on),
                sizeof(on)))
            {
                set_fail_flag();
                TS_RAISE_SYSTEM_ERROR("setsockopt(SO_REUSEADDR) failed");
            }
        }

        if(reuse_port) {
            int const on = 1;
            if(
              -1
              == ::setsockopt(
                file_descriptor_.fd(),
                SOL_SOCKET,
                SO_REUSEPORT,
                std::addressof(on),
                sizeof(on)))
            {
                set_fail_flag();
                TS_RAISE_SYSTEM_ERROR("setsockopt(SO_REUSEPORT) failed");
            }
        }

        sockaddr*    addr{};
        sockaddr_in6 in6 = Addr_t::defaultV6();
        sockaddr_in  in4 = Addr_t::defaultV4();
        socklen_t    length{};

        switch(type) {
        case IP::Type::Any:
            {
                in6.sin6_port          = htons(port);
                in6_addr const anyAddr = IN6ADDR_ANY_INIT;
                in6.sin6_addr          = anyAddr;
                length                 = sizeof(in6);
                addr                   = Addr_t::to_sockaddr(std::addressof(in6));
            }
            break;
        case IP::Type::IPv6:
            {
                int const       enableInt = 1;
                socklen_t const enableIntLength{sizeof(enableInt)};
                if(
                  -1
                  == ::setsockopt(
                    file_descriptor_.fd(),
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    std::addressof(enableInt),
                    enableIntLength))
                {
                    set_fail_flag();
                    TS_RAISE_SYSTEM_ERROR("setsockopt(IPV6_V6ONLY) failed");
                }

                in6.sin6_port          = htons(port);
                in6_addr const anyAddr = IN6ADDR_ANY_INIT;
                in6.sin6_addr          = anyAddr;
                length                 = sizeof(in6);
                addr                   = Addr_t::to_sockaddr(std::addressof(in6));
            }
            break;
        case IP::Type::IPv4:
            {
                in4.sin_port        = htons(port);
                in4.sin_addr.s_addr = INADDR_ANY;
                length              = sizeof(in4);
                addr                = Addr_t::to_sockaddr(std::addressof(in4));
            }
            break;
        }

        if(Socket::is_packet_based_type(socketType_)) {
            enable_pktinfo_();
            multicast_loop(false);
        }

        if(-1 == ::bind(file_descriptor_.fd(), addr, length)) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("bind failed");
        }
    }
#ifdef CAN_RAW
    void Socket_Impl::bind_CAN(std::string const& interface) {
        if(interface.size() > IFNAMSIZ) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "bindCAN failed");
        }

        ifreq ifr{};
        // to access the union to prevent UB
        ifr.ifr_ifrn = decltype(ifr.ifr_ifrn){};
        static_assert(sizeof(ifr.ifr_ifrn.ifrn_name) == IFNAMSIZ, "linux CAN header bad");
        std::copy(begin(interface), end(interface), ifr.ifr_ifrn.ifrn_name);
        if(-1 == ::ioctl(file_descriptor_.fd(), SIOCGIFINDEX, std::addressof(ifr))) {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("ioctl failed");
        }

        sockaddr_can addr{};
        addr.can_family  = AF_CAN;
        addr.can_ifindex = ifr.ifr_ifindex;

        if(
          -1
          == ::bind(
            file_descriptor_.fd(),
            reinterpret_cast<sockaddr*>(std::addressof(addr)),
            sizeof(addr)))
        {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("bind failed");
        }
    }
#endif
#ifdef PF_UNIX
    std::pair<sockaddr_un, socklen_t>
    Socket_Impl::generate_sockaddr_un(std::string const& filename, bool abstract) {
        if(
          filename.size() > (sizeof(sockaddr_un{}.sun_path) - (abstract ? 1 : 0))
          || (!abstract && filename.empty()))
        {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR_CE(EINVAL, "generate_sockaddr_un failed");
        }
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::copy(
          begin(filename),
          end(filename),
          std::next(std::begin(addr.sun_path), abstract ? 1 : 0));
        socklen_t length = sizeof(addr);
        if(abstract) {
            addr.sun_path[0] = '\0';
            if(filename.empty()) {
                length = static_cast<socklen_t>(sizeof(sa_family_t));
            } else {
                length = static_cast<socklen_t>(filename.size() + 1 + sizeof(sa_family_t));
            }
        }
        return {addr, length};
    }

    void Socket_Impl::bind_UNIX_(std::pair<sockaddr_un, socklen_t> const& address) {
        if(
          -1
          == ::bind(
            file_descriptor_.fd(),
            reinterpret_cast<sockaddr const*>(std::addressof(address.first)),
            address.second))
        {
            set_fail_flag();
            TS_RAISE_SYSTEM_ERROR("bind failed");
        }
    }
#endif
    Socket_Impl Socket_Impl::accept(bool needShutdown) {
        auto const oldRecvTimeout = recv_timeout_;
        auto const stoptime       = chrono::calc_stop_time<Clock>(oldRecvTimeout);
        auto const guard          = make_scope_guard(
          [this, oldRecvTimeout]() { set_recv_timeout_(oldRecvTimeout); },
          ScopeGuardCallPolicy::always);
        while(true) {
#ifdef SOCK_CLOEXEC
            int const new_fd = ::accept4(file_descriptor_.fd(), nullptr, nullptr, SOCK_CLOEXEC);
#else
            int const new_fd = ::accept(file_descriptor_.fd(), nullptr, nullptr);
#endif
            if(new_fd == -1) {
                auto errnoCopy = errno;
                if(!is_errno_recoverable(errnoCopy)) {
                    set_fail_flag();
                    TS_RAISE_SYSTEM_ERROR("accept4 failed");
                }
                auto const now = Clock::now();
                if(now >= stoptime) {
                    TS_RAISE_SYSTEM_ERROR_CE(errnoCopy, "accept4 failed");
                }
                set_recv_timeout_(stoptime - now);
            } else {
                return Socket_Impl{FileDescriptor{new_fd}, socketType_, needShutdown};
            }
        }
    }
}}   // namespace ts::detail
