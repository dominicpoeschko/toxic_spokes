# Examples of Toxic Spokes
This readme gives an overview over the examples of several key features of `toxic_spokes` (in the following as `ts`). A basic usecase is the use of the IP functionality. It provides socket communication with remote hosts over the TCP as well as the UDP protocoll.
`ts` provides CAN and serial communication features as well. These features can be used with an USB interface, providing the connection to external hardware.

### Compilation

To compile all the examples in this folder simply use:
```bash
cd examples #if your are not already inside the folder
mkdir build
cd build
cmake ..
make
```

## IP
The IP functionality of `ts` implements the UDP and TCP protocol. The examples can be found in the [IP](IP) folder.
### UDP
#### Basic usage
The basic UDP functions are explained in [IP/udp_basic.cpp](IP/udp_basic.cpp).

This example starts a sever instance on port `2913` and checks if the server is up and running. After that a client instance connects to the server and sends test data. The data received from the server is collected and compared to the sent data.

### TCP
#### Basic usage
The basic TCP functions are explained in [IP/tcp_basic.cpp](IP/tcp_basic.cpp).

This example starts a sever instance on port `2913` and checks if the server is up and running. After that a client instance wants to connect to the server. After accepting the client, data can be received. The data received from the server is then compared to the sent data.

## CAN
`ts` supports CAN communication as well. It implements CAN classic and CAN flexible datarate.
> Note: CAN FD is currently supported but not tested. A use of the CAN FD class like in the example will not compile!

### CAN Classic
An example of the communication with the CAN Classic functionality can be found in [CAN/can.cpp](CAN/can.cpp).

### CAN FD
An commented out example of the CAN FD functionality can be found in [CAN/can_fd.cpp](CAN/can_fd.cpp).
> Note: CAN FD is currently supported but not tested. A use of the CAN FD class like in the example will not compile!

## Serial
`ts` also supports serial communication through the serial devices of Linux.

### UART
An example of the communication through an `UART` interface is given in [Serial/uart.cpp](Serial/uart.cpp). 
The example sends a string to the output of a hardware UART interface. This output is connected to the input of the same interface.
All data sent is received from the example and written into a input buffer.
The programm succeeds if the sent and received strings are equal.
