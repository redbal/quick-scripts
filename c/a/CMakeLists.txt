cmake_minimum_required(VERSION 3.13)  # CMake version check

project(MyProj)
project(assembler C ASM) 

enable_language(ASM_NASM)
set(CMAKE_ASM_NASM_COMPILE_OBJECT "<CMAKE_ASM_NASM_COMPILER> <INCLUDES> <FLAGS> -o <OBJECT> <SOURCE>")

add_compile_options(
    "$<$<COMPILE_LANGUAGE:ASM_NASM>:-fPIC $<IF:$<BOOL:$<TARGET_PROPERTY:NASM_OBJ_FORMAT>>, \
    $<TARGET_PROPERTY:NASM_OBJ_FORMAT>, ${CMAKE_ASM_NASM_OBJECT_FORMAT}>>"
)

add_executable(printA.o printA.s)
set_target_properties(printA.o PROPERTIES NASM_OBJ_FORMAT elf64)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set_source_files_properties(printA.s PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp")

add_executable(one printA.s one.c)

set(BUILD_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(BUILD_BIN ${BUILD_ROOT}/bin)

install(TARGETS one DESTINATION ${BUILD_BIN})