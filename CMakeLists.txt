cmake_minimum_required(VERSION 3.2)
set (CMAKE_CXX_STANDARD 11)

project(saruman CXX)
include_directories(elfio-3.2 tclap-1.2.1/include/)

#add_executable(saruman saruman.cpp)
add_executable(objcat objcat.cpp common.cpp)
add_executable(objinfo objinfo.cpp common.cpp)
add_executable(objpatch objpatch.cpp common.cpp)


