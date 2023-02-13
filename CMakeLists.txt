cmake_minimum_required(VERSION 3.18)

project(toxic_spokes)

add_library(toxic_spokes src/toxic_spokes/Serial/Serial.cpp)
target_include_directories(toxic_spokes PUBLIC src)

add_library(toxic_spokes::toxic_spokes ALIAS toxic_spokes)
