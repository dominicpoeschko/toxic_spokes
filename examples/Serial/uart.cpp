#include "toxic_spokes/Serial/Serial.hpp"
#include <array>
#include <cstddef>
#include <span>
#include <cassert>
#include <string_view>

int main(){
    static constexpr size_t baudRate{115200};
    static constexpr std::string_view sendString{"Test1234"};
    ts::Serial serialDevice{"/dev/serial/by-id/usb-Dominic_UART-ISOLATOR_DA3G6WYJ-if00-port0", baudRate};
    assert(serialDevice.is_valid());
    serialDevice.send(std::as_bytes(std::span{sendString}));

    std::array<char, sendString.size()> recvBuffer;
    auto const recvSize = serialDevice.recv(std::as_writable_bytes(std::span{recvBuffer}));
    std::string_view const recvString{recvBuffer.begin(), recvSize};
    assert(recvString == sendString);
    return 0;
}