#include "toxic_spokes/CAN/CAN_Socket.hpp"
#include <fmt/format.h>
#include <cstddef>
#include <cassert>

int main(){
    //CAN FD not working now since the software is not tested with proper hardware!
    /*
    ts::CANFD_Socket socket{"path/to/device"};
    assert(socket.is_valid());
    */
    while(1){
        /*
        ts::CANFD_Socket::Message send_msg{};
        send_msg.id = 0;
        send_msg.size = 1;
        send_msg.data[0] = std::byte{1};
        send_msg.data[1] = std::byte{2};
        send_msg.data[2] = std::byte{3};
        send_msg.data[3] = std::byte{0};
        socket.send(send_msg);

        auto const recv_msg = socket.recv();
        fmt::print("New Message:\nID: {}\nSize: {}\nData: {}\n", 
                    recv_msg.id, recv_msg.size, fmt::join(recv_msg.data, ", "));
        */
    }
    
    
}
