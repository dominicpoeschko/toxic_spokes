#pragma once

#include "toxic_spokes/detail/IPAddress.hpp"

#include <chrono>
#include <stdexcept>
#include <sys/time.h>

namespace ts { namespace detail {
    template<typename It, typename T>
    It next(It it, T count) {
        return std::next(it, static_cast<typename std::make_signed<T>::type>(count));
    }

}}   // namespace ts::detail

namespace ts {
template<typename dummy>
struct Com_Transmit_Exception_ : std::runtime_error {
    enum class Type {
        send_timeout,
        recv_timeout,
        buffer_to_small_for_packet,
        address_error,
        socket_failed
    };
    std::size_t              bytes;
    Type                     type;
    std::optional<IPAddress> src;
    std::optional<IPAddress> dst;
    std::optional<IPAddress> ifa;

    template<typename S>
    Com_Transmit_Exception_(Type type_, std::size_t bytes_, S&& what_arg)
      : runtime_error(std::forward<S>(what_arg))
      , bytes{bytes_}
      , type{type_}
      , src{}
      , dst{}
      , ifa{} {}

    template<typename S>
    Com_Transmit_Exception_(
      Type                     type_,
      std::size_t              bytes_,
      S&&                      what_arg,
      std::optional<IPAddress> src_,
      std::optional<IPAddress> dst_,
      std::optional<IPAddress> ifa_)
      : runtime_error(std::forward<S>(what_arg))
      , bytes{bytes_}
      , type{type_}
      , src{src_}
      , dst{dst_}
      , ifa{ifa_} {}

    Com_Transmit_Exception_(Com_Transmit_Exception_ const& other)                = default;
    Com_Transmit_Exception_& operator=(Com_Transmit_Exception_ const& other)     = default;
    Com_Transmit_Exception_(Com_Transmit_Exception_&& other) noexcept            = default;
    Com_Transmit_Exception_& operator=(Com_Transmit_Exception_&& other) noexcept = default;
};
using Com_Transmit_Exception = Com_Transmit_Exception_<void>;

}   // namespace ts
