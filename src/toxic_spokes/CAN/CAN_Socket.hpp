#pragma once
#include "toxic_spokes/detail/FileDescriptor.hpp"
#include "toxic_spokes/detail/Socket_Impl.hpp"

#include <array>
#include <cstring>
#include <string>

namespace ts {
namespace detail {
    template<bool CANFD>
    class CAN_Socket_Impl : protected detail::Socket_Impl {
    protected:
        explicit CAN_Socket_Impl(detail::Socket_Impl::Fd_t fd)
          : Socket_Impl(std::move(fd), Socket::Type::RAW, true) {}

        static_assert(CANFD == false);

        using frame_t = std::conditional_t<CANFD, canfd_frame, can_frame>;

    public:
        struct Message {
            std::uint32_t                         id;
            std::size_t                           size;
            std::array<std::byte, CANFD ? 64 : 8> data;
        };

        explicit CAN_Socket_Impl(std::string const& interface)
          : Socket_Impl{Socket::Domain::CAN, Socket::Type::RAW, Socket::Protocol::CAN, false} {
            bind_CAN(interface);
        }

        void send(Message const& data) {
            if(data.size > 8) {
                TS_RAISE(std::runtime_error, "size wrong");
            }
            if(data.id > 0x1FFFFFFF) {
                TS_RAISE(std::runtime_error, "id wrong");
            }
            frame_t msg;
            msg.len    = data.size;
            msg.can_id = data.id;

            if(data.id > 0x7FF) {
                msg.can_id |= CAN_EFF_FLAG;
            }

            std::memcpy(msg.data, data.data.data(), data.size);

            Socket_Impl::send(std::as_bytes(std::span{msg, 1}));
        }

        Message recv() {
            frame_t msg;

            Socket_Impl::recv(std::as_writable_bytes(std::span{msg, 1}));

            Message data;
            data.size = msg.len;
            data.id   = msg.can_id & CAN_ERR_MASK;
            std::memcpy(data.data.data(), msg.data, data.size);
            return data;
        }

        using Socket_Impl::can_recv;
        using Socket_Impl::can_send;
        using Socket_Impl::is_valid;
        using Socket_Impl::operator FileDescriptor::View;
        using Socket_Impl::operator const FileDescriptor::View;
    };
}   // namespace detail

using CAN_Socket   = detail::CAN_Socket_Impl<false>;
using CANFD_Socket = detail::CAN_Socket_Impl<true>;

}   // namespace ts
