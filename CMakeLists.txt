cmake_minimum_required(VERSION 3.25)

project(securepath VERSION 0.1.0 LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not supported; configure with "
        "'cmake --preset default' (or 'cmake -S . -B build'). Remove the "
        "CMakeCache.txt and CMakeFiles/ this attempt just created.")
endif()

# fail with a clear message instead of hundreds of C++26 errors
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
    message(FATAL_ERROR "GCC ${CMAKE_CXX_COMPILER_VERSION} is too old; C++26 support requires GCC 14 or newer")
endif()

option(SECUREPATH_BUILD_TESTS "Build the securepath unit tests" ${PROJECT_IS_TOP_LEVEL})
option(SECUREPATH_BUILD_TEST_FRAME "Build the test_frame helper library (needs Catch2)" ${SECUREPATH_BUILD_TESTS})
option(SECUREPATH_SANITIZE "Build with address and undefined-behaviour sanitizers" OFF)

if(PROJECT_IS_TOP_LEVEL)
    set(CMAKE_CXX_STANDARD 26)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    # for clangd and other tooling; a compile_commands.json symlink at the
    # source root may point into the build directory
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Debug)
        message(STATUS "Enabling debug build")
    endif()
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -ggdb")
endif()

if(SECUREPATH_BUILD_TESTS)
    enable_testing()
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(securepath)

if(SECUREPATH_BUILD_TESTS OR SECUREPATH_BUILD_TEST_FRAME)
    securepath_ensure_catch2()
endif()

add_subdirectory(securepath)
