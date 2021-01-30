cmake_minimum_required(VERSION 3.13)  # CMake version check

project(MyProj)

add_executable(myprog2 fork.c)

set(BUILD_BIN ${CMAKE_CURRENT_SOURCE_DIR}/bin)

install(TARGETS myprog2 DESTINATION ${BUILD_BIN})
