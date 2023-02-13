#pragma once

#include "toxic_spokes/detail/Socket_Impl.hpp"
namespace ts {

using TCP_ClientSocket = detail::Bound_ClientSocket<Socket::Protocol::TCP, Socket::Type::STREAM>;
using TCP_ServerSocket = detail::Bound_ServerSocket<Socket::Protocol::TCP, Socket::Type::STREAM>;

#ifdef IPPROTO_SCTP
using SCTP_Stream_ClientSocket
  = detail::Bound_ClientSocket<Socket::Protocol::SCTP, Socket::Type::STREAM>;
using SCTP_Stream_ServerSocket
  = detail::Bound_ServerSocket<Socket::Protocol::SCTP, Socket::Type::STREAM>;

using SCTP_Packet_ClientSocket
  = detail::Unbound_ClientSocket<Socket::Protocol::SCTP, Socket::Type::SEQPACKET>;
using SCTP_Packet_ServerSocket
  = detail::Unbound_Listening_ServerSocket<Socket::Protocol::SCTP, Socket::Type::SEQPACKET>;
#endif

using UDP_Bound_ClientSocket
  = detail::Bound_ClientSocket<Socket::Protocol::UDP, Socket::Type::DGRAM>;
using UDP_ClientSocket = detail::Unbound_ClientSocket<Socket::Protocol::UDP, Socket::Type::DGRAM>;
using UDP_ServerSocket = detail::Unbound_ServerSocket<Socket::Protocol::UDP, Socket::Type::DGRAM>;

}   // namespace ts
