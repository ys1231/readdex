cmake_minimum_required(VERSION 3.22)
project(readdex)

set(CMAKE_CXX_STANDARD 17)
# 设置运行输出目录为当前源码目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
include_directories(.)
include_directories(resources)
add_executable(readdex
        sourceh/modifiers.cc
        sourceh/modifiers.h
        myuleb128.h
        main.cpp
        readDex.cpp
        readDex.h)
