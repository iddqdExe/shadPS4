// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <functional>
#include <stdexcept>

#include <gtest/gtest.h>

#include "bbcoop/core/scoped_entry.h"

using BBCoop::Core::ScopedEntry;

TEST(ScopedEntryTest, FirstEntryTakesTheFlagAndReleasesItOnExit) {
    bool flag = false;
    {
        ScopedEntry entry(flag);
        EXPECT_TRUE(entry);
        EXPECT_TRUE(flag);
    }
    EXPECT_FALSE(flag);
}

TEST(ScopedEntryTest, NestedEntryIsRefusedAndDoesNotReleaseTheOuterFlag) {
    bool flag = false;
    ScopedEntry outer(flag);
    ASSERT_TRUE(outer);
    {
        ScopedEntry inner(flag);
        EXPECT_FALSE(inner);
        EXPECT_TRUE(flag);
    }
    EXPECT_TRUE(flag);
}

TEST(ScopedEntryTest, CanBeEnteredAgainAfterTheScopeEnded) {
    bool flag = false;
    {
        ScopedEntry first(flag);
    }
    ScopedEntry second(flag);
    EXPECT_TRUE(second);
}

TEST(ScopedEntryTest, ReleasesTheFlagWhenAnExceptionLeavesTheScope) {
    bool flag = false;
    try {
        ScopedEntry entry(flag);
        ASSERT_TRUE(entry);
        throw std::runtime_error("boom");
    } catch (const std::runtime_error&) {
    }
    EXPECT_FALSE(flag);
}

namespace {
/// The shape of the game-thread tick: a task that reaches the tick again (a game function called
/// by CallGame running the hooked per-frame code) must not start a nested tick.
struct MiniTick {
    bool in_tick = false;
    int runs = 0;
    int skipped = 0;
    std::function<void()> task;

    void Tick() {
        ScopedEntry entry(in_tick);
        if (!entry) {
            ++skipped;
            return;
        }
        ++runs;
        if (task) {
            task();
        }
    }
};
} // namespace

TEST(ScopedEntryTest, ATaskThatReachesTheTickAgainRunsNoNestedTick) {
    MiniTick tick;
    tick.task = [&tick] { tick.Tick(); };
    tick.Tick();
    EXPECT_EQ(tick.runs, 1);
    EXPECT_EQ(tick.skipped, 1);
    EXPECT_FALSE(tick.in_tick);
    // The next frame ticks normally.
    tick.Tick();
    EXPECT_EQ(tick.runs, 2);
    EXPECT_EQ(tick.skipped, 2);
}
