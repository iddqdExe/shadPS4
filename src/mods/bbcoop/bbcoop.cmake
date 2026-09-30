# SPDX-FileCopyrightText: 2026 BB Co-op contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# BB Co-op mod. Included from the top-level CMakeLists.txt after the shadps4 target exists.
# bbcoop_core holds pure logic with no emulator dependencies (unit-tested on the host);
# its include root is src/mods, so it cannot see emulator headers by accident.
# Runtime glue that touches emulator internals is compiled into the shadps4 target.

option(BBCOOP_TESTS "Build BB Co-op unit tests" OFF)

set(BBCOOP_DIR ${CMAKE_CURRENT_LIST_DIR})

add_library(bbcoop_core STATIC
    ${BBCOOP_DIR}/core/config.cpp
    ${BBCOOP_DIR}/core/config.h
)
# The top-level CMakeLists.txt calls include_directories(src) for the whole directory tree, and every
# target inherits it. Clear the inherited list so bbcoop_core really only sees src/mods.
set_target_properties(bbcoop_core PROPERTIES INCLUDE_DIRECTORIES "")
target_include_directories(bbcoop_core PUBLIC ${CMAKE_SOURCE_DIR}/src/mods)
target_link_libraries(bbcoop_core PUBLIC fmt::fmt toml11::toml11)

target_link_libraries(shadps4 PRIVATE bbcoop_core)

if (BBCOOP_TESTS)
    enable_testing()
    add_subdirectory(${BBCOOP_DIR}/tests ${CMAKE_BINARY_DIR}/bbcoop_tests)
endif()
