# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/credd/code/c/a

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/credd/code/c/a

# Include any dependencies generated for this target.
include CMakeFiles/printA.o.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/printA.o.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/printA.o.dir/flags.make

CMakeFiles/printA.o.dir/printA.s.o: CMakeFiles/printA.o.dir/flags.make
CMakeFiles/printA.o.dir/printA.s.o: printA.s
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/credd/code/c/a/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building ASM object CMakeFiles/printA.o.dir/printA.s.o"
	/usr/bin/cc $(ASM_DEFINES) $(ASM_INCLUDES) $(ASM_FLAGS) -x assembler-with-cpp -o CMakeFiles/printA.o.dir/printA.s.o -c /home/credd/code/c/a/printA.s

# Object files for target printA.o
printA_o_OBJECTS = \
"CMakeFiles/printA.o.dir/printA.s.o"

# External object files for target printA.o
printA_o_EXTERNAL_OBJECTS =

printA.o: CMakeFiles/printA.o.dir/printA.s.o
printA.o: CMakeFiles/printA.o.dir/build.make
printA.o: CMakeFiles/printA.o.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/credd/code/c/a/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking ASM executable printA.o"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/printA.o.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/printA.o.dir/build: printA.o

.PHONY : CMakeFiles/printA.o.dir/build

CMakeFiles/printA.o.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/printA.o.dir/cmake_clean.cmake
.PHONY : CMakeFiles/printA.o.dir/clean

CMakeFiles/printA.o.dir/depend:
	cd /home/credd/code/c/a && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/credd/code/c/a /home/credd/code/c/a /home/credd/code/c/a /home/credd/code/c/a /home/credd/code/c/a/CMakeFiles/printA.o.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/printA.o.dir/depend

