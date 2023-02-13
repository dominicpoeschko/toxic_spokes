#pragma once

#include "toxic_spokes/detail/FileDescriptor.hpp"
#include "toxic_spokes/detail/IPAddress.hpp"
#include "toxic_spokes/detail/chrono_helper.hpp"
#include "toxic_spokes/detail/com_common.hpp"
#include "toxic_spokes/detail/raise.hpp"
#include "toxic_spokes/detail/socket_common.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/un.h>
#include <system_error>
#include <utility>
#include <vector>

namespace ts { namespace detail {
    class Socket_Impl {
    public:
        Socket_Impl(Socket_Impl const& other)                = delete;
        Socket_Impl& operator=(Socket_Impl const& other)     = delete;
        Socket_Impl(Socket_Impl&& other) noexcept            = default;
        Socket_Impl& operator=(Socket_Impl&& other) noexcept = default;
        ~Socket_Impl() noexcept;

        explicit operator FileDescriptor::View() noexcept;
        explicit operator const FileDescriptor::View() const noexcept;

        using Addr_t = IPAddress;
        using Fd_t   = FileDescriptor;
        using IPType = IP::Type;

    protected:
        using Clock = std::chrono::steady_clock;
        static constexpr std::size_t default_max_connections{128};
        static constexpr IP::Type    default_ip_type{
#ifdef IPV6_RECVPKTINFO
          IP::Type::Any
#else
          IP::Type::IPv4
#endif
        };

        static constexpr auto default_connect_timeout{std::chrono::seconds{5}};

        Socket_Impl() = delete;
        Socket_Impl(Socket::Type type, bool needShutdown);
        Socket_Impl(
          Socket::Domain   domain,
          Socket::Type     type,
          Socket::Protocol protocol,
          bool             needShutdown);
        Socket_Impl(FileDescriptor fd, Socket::Type type, bool needShutdown);

        std::vector<Addr_t> get_bound_interface_addresses();

        void enable_broadcast(bool enable);

        void join_multicast_group(Addr_t const& multicast_addr);
        void leave_multicast_group(Addr_t const& multicast_addr);
        void multicast_loop(bool enable);

        void   shutdown_recv();
        void   shutdown_send();
        void   shutdown();
        Addr_t get_address();
        Addr_t get_peer_address();

        std::string get_peer_file_name();

        bool is_valid() noexcept;

        FileDescriptor release_FD() noexcept;

        std::size_t send(std::span<std::byte const> buffer);
        std::size_t send_nonblocking(std::span<std::byte const> buffer);
        std::size_t recv(std::span<std::byte> buffer);
        std::size_t recv_nonblocking(std::span<std::byte> buffer);
        std::size_t peek(std::span<std::byte> buffer);
        std::size_t peek_nonblocking(std::span<std::byte> buffer);

        std::size_t sendto(Addr_t const& dst, std::span<std::byte const> buffer);
        std::size_t sendto_nonblocking(Addr_t const& dst, std::span<std::byte const> buffer);

        std::size_t recvfrom(Addr_t* src, std::span<std::byte> buffer);
        std::size_t recvfrom(Addr_t* src, Addr_t* dst, std::span<std::byte> buffer);
        std::size_t recvfrom(Addr_t* src, Addr_t* dst, Addr_t* ifa, std::span<std::byte> buffer);
        std::size_t recvfrom_nonblocking(Addr_t* src, std::span<std::byte> buffer);

        std::size_t peekfrom(Addr_t* src, std::span<std::byte> buffer);
        std::size_t peekfrom(Addr_t* src, Addr_t* dst, std::span<std::byte> buffer);
        std::size_t peekfrom(Addr_t* src, Addr_t* dst, Addr_t* ifa, std::span<std::byte> buffer);
        std::size_t peekfrom_nonblocking(Addr_t* src, std::span<std::byte> buffer);

        template<typename Rep, typename Period>
        void set_recv_timeout(std::chrono::duration<Rep, Period> const& timeout) {
            set_recv_timeout_(
              ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout));
        }

        template<typename Rep, typename Period>
        void set_send_timeout(std::chrono::duration<Rep, Period> const& timeout) {
            set_send_timeout_(
              ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout));
        }

        template<typename Rep, typename Period>
        bool can_recv(std::chrono::duration<Rep, Period> const& timeout) {
            return file_descriptor_.can_recv(timeout);
        }

        template<typename Rep, typename Period>
        bool can_send(std::chrono::duration<Rep, Period> const& timeout) {
            return file_descriptor_.can_send(timeout);
        }

        std::size_t bytes_available();

        // can be exposed by child
        // using Socket_Impl::bytes_available;
        // using Socket_Impl::can_recv;
        // using Socket_Impl::can_send;
        // using Socket_Impl::default_connect_timeout;
        // using Socket_Impl::default_ip_type;
        // using Socket_Impl::default_max_connections;
        // using Socket_Impl::enable_broadcast;
        // using Socket_Impl::get_address;
        // using Socket_Impl::get_peer_address;
        // using Socket_Impl::is_valid;
        // using Socket_Impl::join_multicast_group;
        // using Socket_Impl::leave_multicast_group;
        // using Socket_Impl::peek;
        // using Socket_Impl::peekfrom;
        // using Socket_Impl::peekfrom_nonblocking;
        // using Socket_Impl::peek_nonblocking;
        // using Socket_Impl::recv;
        // using Socket_Impl::recvfrom;
        // using Socket_Impl::recvfrom_nonblocking;
        // using Socket_Impl::recv_nonblocking;
        // using Socket_Impl::release_FD;
        // using Socket_Impl::send;
        // using Socket_Impl::send_nonblocking;
        // using Socket_Impl::sendto;
        // using Socket_Impl::sendto_nonblocking;
        // using Socket_Impl::set_recv_timeout;
        // using Socket_Impl::set_send_timeout;
        // using Socket_Impl::shutdown;
        // using Socket_Impl::shutdown_recv;
        // using Socket_Impl::shutdown_send;

        // should not be exposed by child
        template<typename Rep, typename Period>
        void create_connect(
          std::string const&                 host,
          std::uint16_t                      port,
          Socket::Type                       sockettype,
          Socket::Protocol                   protocol,
          IP::Type                           type,
          std::chrono::duration<Rep, Period> timeout) {
            auto addresses = Addr_t::resolve(host, port, sockettype, protocol, type);
            if(addresses.empty()) {
                TS_RAISE(std::runtime_error, "connect failed: no host resolved");
            }
            create_connect_(
              sockettype,
              protocol,
              addresses,
              ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout));
        }

        // should not be exposed by child
        template<typename Rep, typename Period>
        void create_connect(
          Addr_t const&                      addr,
          Socket::Type                       sockettype,
          Socket::Protocol                   protocol,
          std::chrono::duration<Rep, Period> timeout) {
            std::vector<Addr_t> addresses;
            addresses.push_back(addr);
            create_connect_(
              sockettype,
              protocol,
              addresses,
              ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout));
        }

#ifdef PF_UNIX
        template<typename Rep, typename Period>
        void connect_UNIX(
          Socket::AbstractSocket const&      filename,
          std::chrono::duration<Rep, Period> timeout) {
            connect_UNIX_(
              generate_sockaddr_un(filename.name, true),
              ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout));
        }

        template<typename Rep, typename Period>
        void connect_UNIX(std::string const& filename, std::chrono::duration<Rep, Period> timeout) {
            connect_UNIX_(
              generate_sockaddr_un(filename, false),
              ts::chrono::saturating_duration_cast<std::chrono::nanoseconds>(timeout));
        }
        void bind_UNIX(Socket::AbstractSocket const& filename) {
            bind_UNIX_(generate_sockaddr_un(filename.name, true));
        }
        void bind_UNIX(std::string const& filename) {
            bind_UNIX_(generate_sockaddr_un(filename, false));
        }
        std::string get_file_name();

    private:
        void connect_UNIX_(
          std::pair<sockaddr_un, socklen_t> const& address,
          std::chrono::nanoseconds                 timeout);
        void bind_UNIX_(std::pair<sockaddr_un, socklen_t> const& address);
        std::pair<sockaddr_un, socklen_t>
        generate_sockaddr_un(std::string const& filename, bool abstract);

        std::string get_file_name_(bool peer);

    public:
#endif

        void bind_IP(uint16_t port, IP::Type type, bool reuse_addr, bool reuse_port);
#ifdef CAN_RAW
        void bind_CAN(std::string const& interface);
#endif
        void        listen(std::size_t max_connections);
        Socket_Impl accept(bool needShutdown);

    protected:
        std::chrono::nanoseconds recv_timeout_;
        std::chrono::nanoseconds send_timeout_;
        Socket::Type             socketType_;
        Socket::Domain           socketDomain_;
        Socket::Protocol         socketProtocol_;
        IP::Type                 ipType_;
        bool                     needShutdown_;

    private:
        Fd_t                               file_descriptor_;
        bool                               is_lisening;
        std::unique_ptr<std::atomic<bool>> fail_flag_;

        void enable_pktinfo_();

        bool get_fail_flag();
        void set_fail_flag();

        void
        create_(Socket::Domain domain, Socket::Type type, Socket::Protocol protocol, bool silent);
        void multicast_group_(Addr_t const& multicast_addr, bool join);
        std::pair<sockaddr_storage, socklen_t> get_name_(bool peer);

        void set_timeout_(std::chrono::nanoseconds timeout, int opname);

        void set_recv_timeout_(std::chrono::nanoseconds timeout);
        void set_send_timeout_(std::chrono::nanoseconds timeout);
        void create_connect_(
          Socket::Type               sockettype,
          Socket::Protocol           protocol,
          std::vector<Addr_t> const& partners,
          std::chrono::nanoseconds   timeout);
        void connect_(
          sockaddr const*          address,
          socklen_t                length,
          std::chrono::nanoseconds timeout,
          bool                     silent);
        void connect_IP_(Addr_t const& partner, std::chrono::nanoseconds timeout, bool silent);

        void bind_IP_(std::uint16_t port, IP::Type type, bool reuse_addr, bool reuse_port);
        void handle_self_connect_(Addr_t const& partner);

        std::size_t sendto_int_(
          sockaddr const*            dst,
          socklen_t                  length,
          std::span<std::byte const> buffer,
          int                        flags,
          bool                       useTimeout);
        std::size_t recv_int_(std::span<std::byte> buffer, int flags, bool useTimeout);
        std::size_t recvfrom_int_(
          sockaddr_storage*    src,
          socklen_t*           src_length,
          sockaddr_storage*    dst,
          socklen_t*           dst_length,
          sockaddr_storage*    ifa,
          socklen_t*           ifa_lenght,
          std::span<std::byte> buffer,
          int                  flags,
          bool                 useTimeout);
        std::size_t recvfrom_src_int_(Addr_t* src, std::span<std::byte> buffer, int flags);
        std::size_t
        recvfrom_src_dst_int_(Addr_t* src, Addr_t* dst, std::span<std::byte> buffer, int flags);
        std::size_t recvfrom_src_dst_ifa_int_(
          Addr_t*              src,
          Addr_t*              dst,
          Addr_t*              ifa,
          std::span<std::byte> buffer,
          int                  flags);

        std::vector<Addr_t> get_address_from_interfaces_();

        //TODO abstract away
        bool get_address_from_interface_index_(
          int               if_index,
          int               family,
          sockaddr_storage* ifa,
          socklen_t*        ifa_lenght);
    };

    template<Socket::Protocol Protocol, Socket::Type Type>
    class Bound_ServerSocket;

    template<Socket::Protocol Protocol, Socket::Type Type>
    class Bound_ClientSocket : protected Socket_Impl {
    public:
        using ServerSocket_t = Bound_ServerSocket<Protocol, Type>;
        using ClientSocket_t = Bound_ClientSocket<Protocol, Type>;
        static constexpr bool const isBound{true};
        static constexpr bool const isServer{false};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

    protected:
        explicit Bound_ClientSocket(Socket_Impl s) : Socket_Impl{std::move(s)} {}
        friend ServerSocket_t;

    public:
        using Socket_Impl::Addr_t;
        using Socket_Impl::Fd_t;
        using Socket_Impl::IPType;
        using Socket_Impl::operator FileDescriptor::View;
        using Socket_Impl::operator const FileDescriptor::View;
        using Socket_Impl::bytes_available;
        using Socket_Impl::can_recv;
        using Socket_Impl::can_send;
        using Socket_Impl::default_connect_timeout;
        using Socket_Impl::default_ip_type;
        using Socket_Impl::get_address;
        using Socket_Impl::get_peer_address;
        using Socket_Impl::is_valid;
        using Socket_Impl::peek;
        using Socket_Impl::peek_nonblocking;
        using Socket_Impl::recv;
        using Socket_Impl::recv_nonblocking;
        using Socket_Impl::release_FD;
        using Socket_Impl::send;
        using Socket_Impl::send_nonblocking;
        using Socket_Impl::set_recv_timeout;
        using Socket_Impl::set_send_timeout;
        using Socket_Impl::shutdown;
        using Socket_Impl::shutdown_recv;
        using Socket_Impl::shutdown_send;

        template<typename Rep, typename Period>
        Bound_ClientSocket(
          std::string const&                        host,
          std::uint16_t                             port,
          std::chrono::duration<Rep, Period> const& timeout)
          : Bound_ClientSocket(host, port, timeout, default_ip_type) {}

        Bound_ClientSocket(std::string const& host, std::uint16_t port, IP::Type type)
          : Bound_ClientSocket(host, port, default_connect_timeout, type) {}

        Bound_ClientSocket(std::string const& host, std::uint16_t port)
          : Bound_ClientSocket(host, port, default_connect_timeout, default_ip_type) {}

        template<typename Rep, typename Period>
        Bound_ClientSocket(
          std::string const&                        host,
          std::uint16_t                             port,
          IP::Type                                  type,
          std::chrono::duration<Rep, Period> const& timeout)
          : Bound_ClientSocket(host, port, timeout, type) {}

        template<typename Rep, typename Period>
        Bound_ClientSocket(
          std::string const&                        host,
          std::uint16_t                             port,
          std::chrono::duration<Rep, Period> const& timeout,
          IP::Type                                  type)
          : Socket_Impl{Type, true} {
            create_connect(host, port, Type, Protocol, type, timeout);
        }

        explicit Bound_ClientSocket(Addr_t const& address)
          : Bound_ClientSocket(address, default_connect_timeout) {}

        template<typename Rep, typename Period>
        Bound_ClientSocket(Addr_t const& address, std::chrono::duration<Rep, Period> const& timeout)
          : Socket_Impl{Type, true} {
            create_connect(address, Type, Protocol, timeout);
        }
    };

    template<Socket::Protocol Protocol, Socket::Type Type>
    class Bound_ServerSocket : protected Socket_Impl {
    public:
        using ServerSocket_t = Bound_ServerSocket<Protocol, Type>;
        using ClientSocket_t = Bound_ClientSocket<Protocol, Type>;
        static constexpr bool const isBound{true};
        static constexpr bool const isServer{true};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

        using Socket_Impl::Addr_t;
        using Socket_Impl::Fd_t;
        using Socket_Impl::IPType;
        using Socket_Impl::operator FileDescriptor::View;
        using Socket_Impl::operator const FileDescriptor::View;
        using Socket_Impl::default_ip_type;
        using Socket_Impl::default_max_connections;
        using Socket_Impl::get_address;
        using Socket_Impl::get_bound_interface_addresses;
        using Socket_Impl::is_valid;
        using Socket_Impl::release_FD;
        using Socket_Impl::set_recv_timeout;
        using Socket_Impl::shutdown;

        explicit Bound_ServerSocket(std::uint16_t port)
          : Bound_ServerSocket{port, default_max_connections, default_ip_type} {}

        Bound_ServerSocket(std::uint16_t port, std::size_t max_connections)
          : Bound_ServerSocket{port, max_connections, default_ip_type} {}

        Bound_ServerSocket(std::uint16_t port, IP::Type type)
          : Bound_ServerSocket{port, default_max_connections, type} {}

        Bound_ServerSocket(std::uint16_t port, IP::Type type, std::size_t max_connections)
          : Bound_ServerSocket{port, max_connections, type} {}

        Bound_ServerSocket(std::uint16_t port, std::size_t max_connections, IP::Type type)
          : Socket_Impl{
            type == IP::Type::IPv4 ? Socket::Domain::INET : Socket::Domain::INET6,
            Type,
            Protocol,
            false} {
            bind_IP(port, type, true, false);
            listen(max_connections);
        }

        ClientSocket_t accept() { return ClientSocket_t{Socket_Impl::accept(true)}; }

        template<typename Rep, typename Period>
        bool can_accept(std::chrono::duration<Rep, Period> const& timeout) {
            return Socket_Impl::can_recv(timeout);
        }
    };

    template<Socket::Protocol Protocol, Socket::Type Type>
    class Unbound_ServerSocket;

    template<Socket::Protocol Protocol, Socket::Type Type>
    class Unbound_ClientSocket : protected Socket_Impl {
    protected:
        Addr_t address_;

    public:
        using ServerSocket_t = Unbound_ServerSocket<Protocol, Type>;
        using ClientSocket_t = Unbound_ClientSocket<Protocol, Type>;
        static constexpr bool const isBound{false};
        static constexpr bool const isServer{false};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

        using Socket_Impl::Addr_t;
        using Socket_Impl::Fd_t;
        using Socket_Impl::IPType;
        using Socket_Impl::operator FileDescriptor::View;
        using Socket_Impl::operator const FileDescriptor::View;
        using Socket_Impl::bytes_available;
        using Socket_Impl::can_recv;
        using Socket_Impl::can_send;
        using Socket_Impl::default_connect_timeout;
        using Socket_Impl::default_ip_type;
        using Socket_Impl::enable_broadcast;
        using Socket_Impl::get_address;
        using Socket_Impl::is_valid;
        using Socket_Impl::join_multicast_group;
        using Socket_Impl::leave_multicast_group;
        using Socket_Impl::multicast_loop;
        using Socket_Impl::peek;
        using Socket_Impl::peek_nonblocking;
        using Socket_Impl::peekfrom;
        using Socket_Impl::peekfrom_nonblocking;
        using Socket_Impl::recv;
        using Socket_Impl::recv_nonblocking;
        using Socket_Impl::recvfrom;
        using Socket_Impl::recvfrom_nonblocking;
        using Socket_Impl::set_recv_timeout;
        using Socket_Impl::set_send_timeout;

        std::size_t send(std::span<std::byte const> buffer) {
            return Socket_Impl::sendto(address_, buffer);
        }
        std::size_t send_nonblocking(std::span<std::byte const> buffer) {
            return Socket_Impl::sendto_nonblocking(address_, buffer);
        }

        Addr_t get_peer_address() const { return address_; }

        Unbound_ClientSocket(std::string const& host, std::uint16_t port)
          : Unbound_ClientSocket(host, port, default_ip_type) {}

        Unbound_ClientSocket(std::string const& host, std::uint16_t port, IP::Type type)
          : Socket_Impl{type == IP::Type::IPv4 ? Socket::Domain::INET : Socket::Domain::INET6, Type, Protocol, false}
          , address_{host, port, Type, Protocol, type} {}

        explicit Unbound_ClientSocket(Addr_t const& address)
          : Socket_Impl{address.isIPv4() ? Socket::Domain::INET : Socket::Domain::INET6, Type, Protocol, false}
          , address_{address} {}
    };

    template<Socket::Protocol Protocol, Socket::Type Type>
    class Unbound_ServerSocket : protected Socket_Impl {
    public:
        using ServerSocket_t = Unbound_ServerSocket<Protocol, Type>;
        using ClientSocket_t = Unbound_ClientSocket<Protocol, Type>;
        static constexpr bool const isBound{false};
        static constexpr bool const isServer{true};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

        using Socket_Impl::Addr_t;
        using Socket_Impl::Fd_t;
        using Socket_Impl::IPType;
        using Socket_Impl::operator FileDescriptor::View;
        using Socket_Impl::operator const FileDescriptor::View;
        using Socket_Impl::bytes_available;
        using Socket_Impl::can_recv;
        using Socket_Impl::can_send;
        using Socket_Impl::default_ip_type;
        using Socket_Impl::enable_broadcast;
        using Socket_Impl::get_address;
        using Socket_Impl::is_valid;
        using Socket_Impl::join_multicast_group;
        using Socket_Impl::leave_multicast_group;
        using Socket_Impl::multicast_loop;
        using Socket_Impl::peek;
        using Socket_Impl::peekfrom;
        using Socket_Impl::peekfrom_nonblocking;
        using Socket_Impl::recv;
        using Socket_Impl::recvfrom;
        using Socket_Impl::recvfrom_nonblocking;
        using Socket_Impl::release_FD;
        using Socket_Impl::sendto;
        using Socket_Impl::sendto_nonblocking;
        using Socket_Impl::set_recv_timeout;
        using Socket_Impl::set_send_timeout;

        explicit Unbound_ServerSocket(std::uint16_t port)
          : Unbound_ServerSocket{port, default_ip_type} {}

        Unbound_ServerSocket(std::uint16_t port, bool reuse_port)
          : Unbound_ServerSocket{port, default_ip_type, reuse_port} {}

        Unbound_ServerSocket(std::uint16_t port, IP::Type type)
          : Unbound_ServerSocket{port, type, false} {}

        Unbound_ServerSocket(std::uint16_t port, bool reuse_port, IP::Type type)
          : Unbound_ServerSocket{port, type, reuse_port} {}

        Unbound_ServerSocket(std::uint16_t port, IP::Type type, bool reuse_port)
          : Socket_Impl{
            type == IP::Type::IPv4 ? Socket::Domain::INET : Socket::Domain::INET6,
            Type,
            Protocol,
            false} {
            bind_IP(port, type, true, reuse_port);
        }
    };

    template<Socket::Protocol Protocol, Socket::Type Type>
    class Unbound_Listening_ServerSocket : protected Socket_Impl {
    public:
        using ServerSocket_t = Unbound_Listening_ServerSocket<Protocol, Type>;
        using ClientSocket_t = Unbound_ClientSocket<Protocol, Type>;
        static constexpr bool const isBound{false};
        static constexpr bool const isServer{true};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

        using Socket_Impl::Addr_t;
        using Socket_Impl::Fd_t;
        using Socket_Impl::IPType;
        using Socket_Impl::operator FileDescriptor::View;
        using Socket_Impl::operator const FileDescriptor::View;
        using Socket_Impl::bytes_available;
        using Socket_Impl::can_recv;
        using Socket_Impl::can_send;
        using Socket_Impl::default_ip_type;
        using Socket_Impl::default_max_connections;
        using Socket_Impl::enable_broadcast;
        using Socket_Impl::get_address;
        using Socket_Impl::is_valid;
        using Socket_Impl::join_multicast_group;
        using Socket_Impl::leave_multicast_group;
        using Socket_Impl::peek;
        using Socket_Impl::peekfrom;
        using Socket_Impl::peekfrom_nonblocking;
        using Socket_Impl::recv;
        using Socket_Impl::recvfrom;
        using Socket_Impl::recvfrom_nonblocking;
        using Socket_Impl::release_FD;
        using Socket_Impl::sendto;
        using Socket_Impl::sendto_nonblocking;
        using Socket_Impl::set_recv_timeout;
        using Socket_Impl::set_send_timeout;

        explicit Unbound_Listening_ServerSocket(std::uint16_t port)
          : Unbound_Listening_ServerSocket{port, default_max_connections, default_ip_type} {}

        Unbound_Listening_ServerSocket(std::uint16_t port, std::size_t max_connections)
          : Unbound_Listening_ServerSocket{port, max_connections, default_ip_type} {}

        Unbound_Listening_ServerSocket(std::uint16_t port, IP::Type type)
          : Unbound_Listening_ServerSocket{port, default_max_connections, type} {}

        Unbound_Listening_ServerSocket(
          std::uint16_t port,
          IP::Type      type,
          std::size_t   max_connections)
          : Unbound_Listening_ServerSocket{port, max_connections, type} {}

        Unbound_Listening_ServerSocket(
          std::uint16_t port,
          std::size_t   max_connections,
          IP::Type      type)
          : Socket_Impl{
            type == IP::Type::IPv4 ? Socket::Domain::INET : Socket::Domain::INET6,
            Type,
            Protocol,
            false} {
            bind_IP(port, type, true, false);
            listen(max_connections);
        }
    };
}}   // namespace ts::detail

#include "Socket_Impl.inl"
