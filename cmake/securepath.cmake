# Helpers shared by every securepath sub-library.
#
# Usage pattern inside a library directory:
#   securepath_add_library(util *.cpp *.hpp)
#   target_link_libraries(util PUBLIC log)
#   securepath_add_test_directory(test)
include_guard(GLOBAL)

# Interface target (securepath::options) carrying the include root and language level; every
# library links it PUBLIC so consumers can write #include <securepath/...>.
add_library(securepath_common INTERFACE)
add_library(securepath::options ALIAS securepath_common)
target_include_directories(securepath_common INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>)
target_compile_features(securepath_common INTERFACE cxx_std_26)

if(SECUREPATH_SANITIZE)
    target_compile_options(securepath_common INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(securepath_common INTERFACE -fsanitize=address,undefined)
endif()

if(MINGW)
    # mingw libstdc++ ships std::print's terminal support in a separate archive
    target_link_libraries(securepath_common INTERFACE stdc++exp)
endif()

# Warnings are private to our own targets so they are not imposed on consumers.
# -Wno-missing-field-initializers: partially initialised aggregates (rest value-initialised) are idiomatic here
set(SECUREPATH_WARNINGS
    -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
    -Werror=return-type -fdiagnostics-color=auto -Wno-deprecated-declarations)

function(securepath_apply_warnings target)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:${SECUREPATH_WARNINGS}>)
endfunction()

# securepath_add_library(<name> <glob>...)
# Static library from the globbed sources (relative to the calling directory),
# exported as both <name> (legacy) and securepath::<name>.
function(securepath_add_library name)
    file(GLOB SRC CONFIGURE_DEPENDS ${ARGN})
    add_library(${name} STATIC ${SRC})
    add_library(securepath::${name} ALIAS ${name})
    target_link_libraries(${name} PUBLIC securepath_common)
    securepath_apply_warnings(${name})
endfunction()

# securepath_add_test(<name> <link-target>...)
# Test executable from all sources in the calling directory, registered with ctest.
function(securepath_add_test name)
    file(GLOB SRC CONFIGURE_DEPENDS *.cpp *.hpp)
    add_executable(${name} ${SRC})
    target_link_libraries(${name} PRIVATE ${ARGN} securepath_common)
    securepath_apply_warnings(${name})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# securepath_add_test_directory(<dir>...)
# add_subdirectory() for test directories, only when tests are enabled.
function(securepath_add_test_directory)
    if(SECUREPATH_BUILD_TESTS)
        foreach(dir IN LISTS ARGN)
            add_subdirectory(${dir})
        endforeach()
    endif()
endfunction()

# Provide Catch2::Catch2 from the bundled submodule unless the consuming
# project already supplies one.
function(securepath_ensure_catch2)
    if(TARGET Catch2::Catch2)
        return()
    endif()
    set(catch2_dir ${PROJECT_SOURCE_DIR}/submodules/catch2)
    if(NOT EXISTS ${catch2_dir}/CMakeLists.txt)
        message(FATAL_ERROR "Catch2 submodule is missing; run 'git submodule update --init'")
    endif()
    add_subdirectory(${catch2_dir} ${CMAKE_BINARY_DIR}/catch2 EXCLUDE_FROM_ALL)
endfunction()
