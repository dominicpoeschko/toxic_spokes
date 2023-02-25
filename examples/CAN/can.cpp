#include "toxic_spokes/CAN/CAN_Socket.hpp"
#include <fmt/format.h>
#include <cstddef>
#include <cassert>

int main(){
    ts::CAN_Socket socket{"path/to/device"};
    assert(socket.is_valid());
    while(1){
        ts::CAN_Socket::Message send_msg{};
        send_msg.id = 0;
        send_msg.size = 1;
        send_msg.data[0] = std::byte{123};
        socket.send(send_msg);

        auto const recv_msg = socket.recv();
        fmt::print("New Message:\nID: {}\nSize: {}\nData: {}\n", 
                    recv_msg.id, recv_msg.size, fmt::join(recv_msg.data, ", "));
    }
    
    
}
