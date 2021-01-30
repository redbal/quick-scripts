add_executable(hello_arm hello_world.c)

set(CMAKE_C_COMPILER "/home/credd/arm64/bin/aarch64-linux-android-gcc")
set(GCC_CONVERAGE_COMPILE_FLAGS "-pie")

add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})

set(BUILD_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(BUILD_BIN ${BUILD_ROOT}/bin)

install(TARGETS hello_arm DESTINATION ${BUILD_BIN})
