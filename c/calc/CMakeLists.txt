#cmake_minimum_required(VERSION 3.13)  # CMake version check
#project(MyProj)
add_executable(calc calc.cpp)
set(BUILD_BIN ${CMAKE_CURRENT_SOURCE_DIR}/bin)
install(TARGETS calc DESTINATION ${BUILD_BIN})
