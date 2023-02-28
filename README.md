# Toxic Spokes
Toxic Spokes is a C++ library to provide socket functionality for IP, CAN and Serial communication.

## Usage
To use this library, you can include it into your existing project by using `git submodules` and adding the following lines to your `CMakeLists.txt`:
```cmake
add_subdirectory(toxic_spokes)
target_link_libraries(
    ${target_name} 
    toxic_spokes::toxic_spokes
    )
```
If you want to use the FetchContent feature of CMake to include the library to your project use the following lines in your `CMakeLists.txt`:
```cmake
include(FetchContent)
FetchContent_Declare(
    toxic_spokes
    GIT_REPOSITORY git@github.com:dominicpoeschko/toxic_spokes.git
    GIT_TAG master
)
FetchContent_MakeAvailable(toxic_spokes)
target_link_libraries(
    ${target_name} 
    toxic_spokes::toxic_spokes
    )
```

### Examples
To build the examples go into the [examples](examples) folder and see the seperate [README.md](examples/README.md).
