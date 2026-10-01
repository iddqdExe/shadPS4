// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include <gtest/gtest.h>

#include "bbcoop/core/call_args.h"

using BBCoop::Core::IsGameCallArg;

namespace {
enum class Slot : std::uint32_t { A };
enum Plain { P };
struct Pair {
    std::uint64_t a;
    std::uint64_t b;
};
} // namespace

TEST(CallArgsTest, AcceptsIntegersEnumsPointersAndFloats) {
    static_assert(IsGameCallArg<std::int32_t>);
    static_assert(IsGameCallArg<std::uint64_t>);
    static_assert(IsGameCallArg<bool>);
    static_assert(IsGameCallArg<char>);
    static_assert(IsGameCallArg<Slot>);
    static_assert(IsGameCallArg<Plain>);
    static_assert(IsGameCallArg<void*>);
    static_assert(IsGameCallArg<const char*>);
    static_assert(IsGameCallArg<Pair*>);
    static_assert(IsGameCallArg<float>);
    static_assert(IsGameCallArg<double>);
    EXPECT_TRUE(IsGameCallArg<std::uint64_t>);
    EXPECT_TRUE(IsGameCallArg<void*>);
}

TEST(CallArgsTest, RejectsEverythingElse) {
    static_assert(!IsGameCallArg<std::string>);
    static_assert(!IsGameCallArg<Pair>);
    static_assert(!IsGameCallArg<std::function<void()>>);
    static_assert(!IsGameCallArg<std::nullptr_t>);
    static_assert(!IsGameCallArg<int&>);
    EXPECT_FALSE(IsGameCallArg<std::string>);
    EXPECT_FALSE(IsGameCallArg<Pair>);
    EXPECT_FALSE(IsGameCallArg<std::nullptr_t>);
}
