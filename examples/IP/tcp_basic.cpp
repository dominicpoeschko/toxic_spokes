#include "toxic_spokes/IP/Socket.hpp"
#include <cassert>
#include <span>
#include <array>

int main(){
    ts::TCP_ServerSocket tcpServer{2913};
    assert(tcpServer.is_valid());
    
    ts::TCP_ClientSocket tcpClient{"localhost", 2913};
    assert(tcpClient.is_valid());
    static constexpr std::string_view sendString{"This is a TCP test...\n"};
    tcpClient.send(std::as_bytes(std::span{sendString}));

    std::array<char, sendString.size()> recvBuffer;
    auto client = tcpServer.accept();
    client.recv(std::as_writable_bytes(std::span{recvBuffer}));
    std::string_view const recvString{recvBuffer.begin(), recvBuffer.size()};
    assert(recvString == sendString);
}