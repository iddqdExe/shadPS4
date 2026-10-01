# SPDX-FileCopyrightText: 2026 BB Co-op contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# BB Co-op mod. Included from the top-level CMakeLists.txt after the shadps4 target exists.
# bbcoop_core holds pure logic with no emulator dependencies (unit-tested on the host);
# its include root is src/mods, so it cannot see emulator headers by accident.
# Runtime glue that touches emulator internals is compiled into the shadps4 target.

option(BBCOOP_TESTS "Build BB Co-op unit tests" OFF)

set(BBCOOP_DIR ${CMAKE_CURRENT_LIST_DIR})

add_library(bbcoop_core STATIC
    ${BBCOOP_DIR}/core/call_args.h
    ${BBCOOP_DIR}/core/config.cpp
    ${BBCOOP_DIR}/core/config.h
    ${BBCOOP_DIR}/core/scoped_entry.h
    ${BBCOOP_DIR}/core/task_queue.h
    ${BBCOOP_DIR}/binding/detour.cpp
    ${BBCOOP_DIR}/binding/detour.h
    ${BBCOOP_DIR}/binding/hook_guard.cpp
    ${BBCOOP_DIR}/binding/hook_guard.h
    ${BBCOOP_DIR}/binding/hook_plan.cpp
    ${BBCOOP_DIR}/binding/hook_plan.h
    ${BBCOOP_DIR}/binding/patch_table.cpp
    ${BBCOOP_DIR}/binding/patch_table.h
    ${BBCOOP_DIR}/binding/relocator.cpp
    ${BBCOOP_DIR}/binding/relocator.h
    ${BBCOOP_DIR}/binding/resolver.cpp
    ${BBCOOP_DIR}/binding/resolver.h
    ${BBCOOP_DIR}/binding/signature.cpp
    ${BBCOOP_DIR}/binding/signature.h
    ${BBCOOP_DIR}/binding/symbols.cpp
    ${BBCOOP_DIR}/binding/symbols.h
    ${BBCOOP_DIR}/binding/data/eu109_image.inc
    ${BBCOOP_DIR}/binding/data/eu109_patches.inc
    ${BBCOOP_DIR}/binding/data/eu109_symbols.inc
)
# The top-level CMakeLists.txt calls include_directories(src) for the whole directory tree, and every
# target inherits it. Clear the inherited list so bbcoop_core really only sees src/mods.
set_target_properties(bbcoop_core PROPERTIES INCLUDE_DIRECTORIES "")
target_include_directories(bbcoop_core PUBLIC ${CMAKE_SOURCE_DIR}/src/mods)
target_link_libraries(bbcoop_core PUBLIC fmt::fmt toml11::toml11 Zydis::Zydis xxHash::xxhash xbyak::xbyak)

# Offline check of the generated EU 1.09 tables against a decrypted eboot (see tools/sigcheck.cpp).
add_executable(bbcoop_sigcheck ${BBCOOP_DIR}/tools/sigcheck.cpp)
# Pure like bbcoop_core: drop the inherited include_directories(src).
set_target_properties(bbcoop_sigcheck PROPERTIES INCLUDE_DIRECTORIES "")
target_link_libraries(bbcoop_sigcheck PRIVATE bbcoop_core)

target_link_libraries(shadps4 PRIVATE bbcoop_core)
target_sources(shadps4 PRIVATE
    ${BBCOOP_DIR}/runtime/binding_runtime.cpp
    ${BBCOOP_DIR}/runtime/binding_runtime.h
    ${BBCOOP_DIR}/runtime/game_thread.cpp
    ${BBCOOP_DIR}/runtime/game_thread.h
    ${BBCOOP_DIR}/runtime/guest_memory.cpp
    ${BBCOOP_DIR}/runtime/guest_memory.h
    ${BBCOOP_DIR}/runtime/hooks.cpp
    ${BBCOOP_DIR}/runtime/hooks.h
    ${BBCOOP_DIR}/runtime/mod.cpp
    ${BBCOOP_DIR}/runtime/mod.h
)

if (BBCOOP_TESTS)
    enable_testing()
    add_subdirectory(${BBCOOP_DIR}/tests ${CMAKE_BINARY_DIR}/bbcoop_tests)
endif()
