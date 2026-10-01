# SPDX-FileCopyrightText: 2026 BB Co-op contributors
# SPDX-License-Identifier: GPL-2.0-or-later

include(FetchContent)
if (NOT TARGET GTest::gtest_main)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE) # gmock is not used and is built by the "all" target
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip)
    FetchContent_MakeAvailable(googletest)

    # googletest builds its own targets with -WX under clang-cl, and clang 22 flags
    # a char8_t -> char32_t conversion in gtest-printers.h (-Wcharacter-conversion).
    # Older clang (e.g. 20.x on GitHub runners) does not know the warning, and under -WX
    # an unknown -Wno-... option is itself an error, so only pass it when it is supported.
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        include(CheckCXXCompilerFlag)
        check_cxx_compiler_flag(-Wno-character-conversion BBCOOP_HAS_WNO_CHARACTER_CONVERSION)
        if (BBCOOP_HAS_WNO_CHARACTER_CONVERSION)
            foreach (gtest_target gtest gtest_main)
                if (TARGET ${gtest_target})
                    target_compile_options(${gtest_target} PRIVATE -Wno-character-conversion)
                endif()
            endforeach()
        endif()
    endif()
endif()
include(GoogleTest)

add_executable(bbcoop_core_tests
    config_test.cpp
    signature_test.cpp
)
# Same isolation as bbcoop_core: drop the include_directories(src) inherited from the top level.
set_target_properties(bbcoop_core_tests PROPERTIES INCLUDE_DIRECTORIES "")
target_link_libraries(bbcoop_core_tests PRIVATE bbcoop_core GTest::gtest_main)
gtest_discover_tests(bbcoop_core_tests TEST_PREFIX "BBCoop." DISCOVERY_MODE PRE_TEST)
