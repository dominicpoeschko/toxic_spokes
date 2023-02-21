#include "toxic_spokes/CAN/CAN_Socket.hpp"
#include <string>
#include <span>
#include <array>
#include <cstddef>
#include <cassert>

int main(){
    ts::CAN_Socket socket{"path/to/device"};
    assert(socket.is_valid());
    ts::CAN_Socket::Message message{};
    message.id = 0;
    message.size = 1;
    socket.send(message);
}