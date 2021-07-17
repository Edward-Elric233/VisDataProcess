cmake_minimum_required(VERSION 3.17)
project(data_process)

set(CMAKE_CXX_STANDARD 14)

include_directories(./lib)

add_executable(data_process src/main.cpp src/data_process.cpp src/ReadFileList.cpp src/json_deal.cpp )
#add_executable(test test/test.cpp)