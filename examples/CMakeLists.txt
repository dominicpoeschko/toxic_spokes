cmake_minimum_required(VERSION 3.18)

project(toxic_spokes_examples)

include(FetchContent)
FetchContent_Declare(
    toxic_spokes
    GIT_REPOSITORY git@github.com:dominicpoeschko/toxic_spokes.git
    GIT_TAG master
)
FetchContent_MakeAvailable(toxic_spokes)

add_executable(can_fd_example CAN/can_fd.cpp)
target_compile_options(can_fd_example PUBLIC -std=c++20)
target_link_libraries(can_fd_example toxic_spokes::toxic_spokes)

add_executable(can_example CAN/can.cpp)
target_compile_options(can_example PUBLIC -std=c++20)
target_link_libraries(can_example toxic_spokes::toxic_spokes)

add_executable(tcp_example IP/tcp.cpp)
target_compile_options(tcp_example PUBLIC -std=c++20)
target_link_libraries(tcp_example toxic_spokes::toxic_spokes)

add_executable(udp_example IP/udp.cpp)
target_compile_options(udp_example PUBLIC -std=c++20)
target_link_libraries(udp_example toxic_spokes::toxic_spokes)

add_executable(uart_example Serial/uart.cpp)
target_compile_options(uart_example PUBLIC -std=c++20)
target_link_libraries(uart_example toxic_spokes::toxic_spokes)