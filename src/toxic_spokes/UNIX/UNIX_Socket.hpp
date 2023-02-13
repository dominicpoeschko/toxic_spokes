#pragma once

#include "toxic_spokes/detail/Socket_Impl.hpp"

#include <string>
#include <unistd.h>

namespace ts {
namespace detail {

    template<Socket::Protocol Protocol, Socket::Type Type>
    class UNIX_ServerSocket_Impl;

    template<Socket::Protocol Protocol, Socket::Type Type>
    class UNIX_ClientSocket_Impl;

    template<Socket::Protocol Protocol, Socket::Type Type>
    class UNIX_ServerSocket_Impl : protected Socket_Impl {
    private:
        std::string filename_;

    public:
        using ServerSocket_t = UNIX_ServerSocket_Impl<Protocol, Type>;
        using ClientSocket_t = UNIX_ClientSocket_Impl<Protocol, Type>;
        static constexpr bool const isBound{true};
        static constexpr bool const isServer{true};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

        using Socket_Impl::default_max_connections;
        using Socket_Impl::get_file_name;
        using Socket_Impl::is_valid;
        using Socket_Impl::release_FD;
        using Socket_Impl::set_recv_timeout;
        using Socket_Impl::shutdown;

        explicit UNIX_ServerSocket_Impl(std::string const& filename)
          : UNIX_ServerSocket_Impl{filename, default_max_connections} {}

        UNIX_ServerSocket_Impl(std::string const& filename, std::size_t max_connections)
          : Socket_Impl{Socket::Domain::UNIX, Type, Protocol, isBound}
          , filename_{filename} {
            bind_UNIX(filename);
            listen(max_connections);
        }

        explicit UNIX_ServerSocket_Impl(Socket::AbstractSocket const& filename)
          : UNIX_ServerSocket_Impl{filename, default_max_connections} {}

        UNIX_ServerSocket_Impl(Socket::AbstractSocket const& filename, std::size_t max_connections)
          : Socket_Impl{Socket::Domain::UNIX, Type, Protocol, isBound} {
            bind_UNIX(filename);
            listen(max_connections);
        }

        UNIX_ServerSocket_Impl(UNIX_ServerSocket_Impl const& other)                = default;
        UNIX_ServerSocket_Impl& operator=(UNIX_ServerSocket_Impl const& other)     = default;
        UNIX_ServerSocket_Impl(UNIX_ServerSocket_Impl&& other) noexcept            = default;
        UNIX_ServerSocket_Impl& operator=(UNIX_ServerSocket_Impl&& other) noexcept = default;

        ~UNIX_ServerSocket_Impl() noexcept {
            if(!filename_.empty()) {
                if(-1 == ::unlink(filename_.c_str())) {
                    TS_RAISE_SYSTEM_ERROR_PRINT_ONLY("unlink failed");
                }
            }
        }

        ClientSocket_t accept() { return ClientSocket_t{Socket_Impl::accept()}; }
    };

    template<Socket::Protocol Protocol>
    class UNIX_ClientSocket_Impl<Protocol, Socket::Type::STREAM> : protected Socket_Impl {
    private:
        static constexpr Socket::Type Type = Socket::Type::STREAM;

    public:
        using ServerSocket_t = UNIX_ServerSocket_Impl<Protocol, Type>;
        using ClientSocket_t = UNIX_ClientSocket_Impl<Protocol, Type>;
        static constexpr bool const isBound{true};
        static constexpr bool const isServer{false};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

    protected:
        explicit UNIX_ClientSocket_Impl(Socket_Impl s) : Socket_Impl{std::move(s)} {}
        friend ServerSocket_t;

    public:
        using Socket_Impl::bytes_available;
        using Socket_Impl::can_recv;
        using Socket_Impl::can_send;
        using Socket_Impl::default_connect_timeout;
        using Socket_Impl::get_file_name;
        using Socket_Impl::get_peer_file_name;
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

        explicit UNIX_ClientSocket_Impl(std::string const& filename)
          : UNIX_ClientSocket_Impl(filename, default_connect_timeout) {}

        template<typename Rep, typename Period>
        UNIX_ClientSocket_Impl(
          std::string const&                        filename,
          std::chrono::duration<Rep, Period> const& timeout)
          : Socket_Impl{Socket::Domain::UNIX, Type, Protocol, isBound} {
            connect_UNIX(filename, timeout);
        }

        explicit UNIX_ClientSocket_Impl(Socket::AbstractSocket const& filename)
          : UNIX_ClientSocket_Impl(filename, default_connect_timeout) {}

        template<typename Rep, typename Period>
        UNIX_ClientSocket_Impl(
          Socket::AbstractSocket const&             filename,
          std::chrono::duration<Rep, Period> const& timeout)
          : Socket_Impl{Socket::Domain::UNIX, Type, Protocol, isBound} {
            connect_UNIX(filename, timeout);
        }
    };

    template<Socket::Protocol Protocol>
    class UNIX_ClientSocket_Impl<Protocol, Socket::Type::SEQPACKET> : protected Socket_Impl {
    private:
        static constexpr Socket::Type Type = Socket::Type::SEQPACKET;

    public:
        using ServerSocket_t = UNIX_ServerSocket_Impl<Protocol, Type>;
        using ClientSocket_t = UNIX_ClientSocket_Impl<Protocol, Type>;
        static constexpr bool const isBound{true};
        static constexpr bool const isServer{false};
        static constexpr bool const isPacketBased{Socket::is_packet_based_type(Type)};

    protected:
        explicit UNIX_ClientSocket_Impl(Socket_Impl s) : Socket_Impl{std::move(s)} {}
        friend ServerSocket_t;

    public:
        using Socket_Impl::bytes_available;
        using Socket_Impl::can_recv;
        using Socket_Impl::can_send;
        using Socket_Impl::default_connect_timeout;
        using Socket_Impl::get_FDView;
        using Socket_Impl::get_file_name;
        using Socket_Impl::get_peer_file_name;
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

        explicit UNIX_ClientSocket_Impl(std::string const& filename)
          : UNIX_ClientSocket_Impl(filename, default_connect_timeout) {}

        template<typename Rep, typename Period>
        UNIX_ClientSocket_Impl(
          std::string const&                        filename,
          std::chrono::duration<Rep, Period> const& timeout)
          : Socket_Impl{Socket::Domain::UNIX, Type, Protocol, isBound} {
            connect_UNIX(filename, timeout);
        }

        explicit UNIX_ClientSocket_Impl(Socket::AbstractSocket const& filename)
          : UNIX_ClientSocket_Impl(filename, default_connect_timeout) {}

        template<typename Rep, typename Period>
        UNIX_ClientSocket_Impl(
          Socket::AbstractSocket const&             filename,
          std::chrono::duration<Rep, Period> const& timeout)
          : Socket_Impl{Socket::Domain::UNIX, Type, Protocol, isBound} {
            connect_UNIX(filename, timeout);
        }
    };

}   // namespace detail

using UNIX_Stream_ClientSocket
  = detail::UNIX_ClientSocket_Impl<Socket::Protocol::DEFAULT, Socket::Type::STREAM>;
using UNIX_Stream_ServerSocket
  = detail::UNIX_ServerSocket_Impl<Socket::Protocol::DEFAULT, Socket::Type::STREAM>;
using UNIX_Packet_ClientSocket
  = detail::UNIX_ClientSocket_Impl<Socket::Protocol::DEFAULT, Socket::Type::SEQPACKET>;
using UNIX_Packet_ServerSocket
  = detail::UNIX_ServerSocket_Impl<Socket::Protocol::DEFAULT, Socket::Type::SEQPACKET>;

template<typename T>
constexpr bool isUnixSocket() {
    if constexpr(
      std::is_same_v<T, UNIX_Packet_ClientSocket> || std::is_same_v<T, UNIX_Packet_ServerSocket>
      || std::is_same_v<T, UNIX_Stream_ClientSocket> || std::is_same_v<T, UNIX_Stream_ServerSocket>)
    {
        return true;
    }
    return false;
}
}   // namespace ts
