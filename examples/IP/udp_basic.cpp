#include "toxic_spokes/IP/Socket.hpp"
#include <cassert>
#include <span>
#include <array>

int main(){
    ts::UDP_ServerSocket udpServer{2913};
    assert(udpServer.is_valid());
    
    ts::UDP_ClientSocket udpClient{"localhost", 2913};
    assert(udpClient.is_valid());
    static constexpr std::string_view sendString{"This is a TCP test...\n"};
    udpClient.send(std::as_bytes(std::span{sendString}));

    std::array<char, sendString.size()> recvBuffer;
    udpServer.recv(std::as_writable_bytes(std::span{recvBuffer}));
    std::string_view const recvString{recvBuffer.begin(), recvBuffer.size()};
    assert(recvString == sendString);
}