cmake_minimum_required(VERSION 3.22)
project(readdex)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
include_directories(resources)

add_executable(readdex
        resources/dex文件格式图.jpeg
        main.cpp
        readDex.cpp
        readDex.h)
