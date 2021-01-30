cmake_minimum_required(VERSION 3.13)  # CMake version check

project(MyProj)

add_executable(myprog1 testA.c)

set(BUILD_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(BUILD_BIN ${BUILD_ROOT}/bin)

add_subdirectory(sub)  #c
add_subdirectory(calc) #cpp
add_subdirectory(arm64) #arm64 c

install(TARGETS myprog1 DESTINATION ${BUILD_BIN})
