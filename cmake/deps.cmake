# Third-party dependency discovery. Each securepath_find_<dep>() sets
# SECUREPATH_HAVE_<DEP> and provides an imported/interface target; libraries
# that need a dependency are skipped (with a status message) when it is absent,
# so a partial tool chain (e.g. the mingw cross-build) still builds the rest.
include_guard(GLOBAL)
include(FetchContent)

# asio (standalone, header-only): a consumer-provided asio::asio target or a
# system copy; building standalone falls back to FetchContent, a consuming
# project instead just gets the asio-dependent components skipped.
# Target: asio::asio
function(securepath_find_asio)
    if(TARGET asio::asio)
        set(SECUREPATH_HAVE_ASIO ON PARENT_SCOPE)
        return()
    endif()
    find_path(ASIO_INCLUDE_DIR asio.hpp)
    if(NOT ASIO_INCLUDE_DIR AND NOT PROJECT_IS_TOP_LEVEL)
        set(SECUREPATH_HAVE_ASIO OFF PARENT_SCOPE)
        message(STATUS "asio: not found; asio-dependent components are skipped")
        return()
    endif()
    if(NOT ASIO_INCLUDE_DIR)
        FetchContent_Declare(asio
            URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-30-2.tar.gz
            URL_HASH SHA256=755bd7f85a4b269c67ae0ea254907c078d408cce8e1a352ad2ed664d233780e8
        )
        FetchContent_MakeAvailable(asio)
        set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include CACHE PATH "asio include directory" FORCE)
    endif()
    add_library(securepath_asio INTERFACE)
    add_library(asio::asio ALIAS securepath_asio)
    target_include_directories(securepath_asio INTERFACE ${ASIO_INCLUDE_DIR})
    find_package(Threads REQUIRED)
    target_link_libraries(securepath_asio INTERFACE Threads::Threads)
    if(WIN32)
        target_link_libraries(securepath_asio INTERFACE ws2_32 mswsock)
        # asio needs the windows target version; MSVC has no default (mingw does)
        target_compile_definitions(securepath_asio INTERFACE _WIN32_WINNT=0x0A00)
    endif()
    message(STATUS "asio: ${ASIO_INCLUDE_DIR}")
    set(SECUREPATH_HAVE_ASIO ON PARENT_SCOPE)
endfunction()

# SQLite3. Target: SQLite3::SQLite3
function(securepath_find_sqlite3)
    find_package(SQLite3)
    set(SECUREPATH_HAVE_SQLITE3 ${SQLite3_FOUND} PARENT_SCOPE)
    if(SQLite3_FOUND)
        if(NOT TARGET SQLite3::SQLite3) # CMake < 4.3 only defines SQLite::SQLite3
            add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
        endif()
        message(STATUS "sqlite3: ${SQLite3_VERSION}")
    else()
        message(STATUS "sqlite3: not found; database library is skipped")
    endif()
endfunction()

# ALSA (linux audio backend). Target: ALSA::ALSA
function(securepath_find_alsa)
    if(WIN32)
        # the audio library uses the DirectSound backend on windows
        set(SECUREPATH_HAVE_ALSA OFF PARENT_SCOPE)
        return()
    endif()
    find_package(ALSA)
    set(SECUREPATH_HAVE_ALSA ${ALSA_FOUND} PARENT_SCOPE)
    if(ALSA_FOUND)
        message(STATUS "alsa: ${ALSA_VERSION_STRING}")
    else()
        message(STATUS "alsa: not found; the audio library has no backend")
    endif()
endfunction()

# ncurses (wide-char). Target: Curses::Curses
function(securepath_find_curses)
    set(CURSES_NEED_WIDE TRUE)
    set(CURSES_NEED_NCURSES TRUE)
    find_package(Curses)
    set(SECUREPATH_HAVE_CURSES ${CURSES_FOUND} PARENT_SCOPE)
    if(CURSES_FOUND AND NOT TARGET Curses::Curses)
        # FindCurses only sets variables; expose them as a target
        add_library(securepath_curses INTERFACE)
        add_library(Curses::Curses ALIAS securepath_curses)
        target_include_directories(securepath_curses INTERFACE ${CURSES_INCLUDE_DIRS})
        target_link_libraries(securepath_curses INTERFACE ${CURSES_LIBRARIES})
        target_compile_definitions(securepath_curses INTERFACE ${CURSES_CFLAGS})
    endif()
    if(CURSES_FOUND)
        message(STATUS "curses: ${CURSES_LIBRARIES}")
    else()
        message(STATUS "curses: not found; console library is skipped")
    endif()
endfunction()

# Botan 3 (>= 3.9 for ML-KEM/ML-DSA). Target: Botan::Botan
function(securepath_find_botan)
    find_package(Botan 3.9 CONFIG QUIET)
    if(NOT Botan_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(BOTAN QUIET IMPORTED_TARGET botan-3>=3.9)
            if(BOTAN_FOUND)
                add_library(Botan::Botan ALIAS PkgConfig::BOTAN)
                set(Botan_FOUND ON)
                set(Botan_VERSION ${BOTAN_VERSION})
            endif()
        endif()
    endif()
    set(SECUREPATH_HAVE_BOTAN ${Botan_FOUND} PARENT_SCOPE)
    if(Botan_FOUND)
        message(STATUS "botan: ${Botan_VERSION}")
    else()
        message(STATUS "botan: not found; crypto library is skipped")
    endif()
endfunction()
