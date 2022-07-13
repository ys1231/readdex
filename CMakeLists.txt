cmake_minimum_required(VERSION 3.22)
project(readdex)

set(CMAKE_CXX_STANDARD 14)
# 设置运行输出目录为当前源码目录
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
include_directories(.)
include_directories(resources)
# 大坑忘记添加两个需要导入的源码文件 导致编译不过 这种低级的错误 不能再犯
add_executable(readdex
        sourceh/modifiers.cc
        sourceh/modifiers.h
        resources/dex文件格式图.jpeg
        main.cpp
        readDex.cpp
        readDex.h)
