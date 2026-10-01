// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "bbcoop/core/task_queue.h"

using BBCoop::Core::BoundedTaskQueue;

TEST(TaskQueueTest, DrainsInFifoOrder) {
    BoundedTaskQueue<int> q(4);
    EXPECT_TRUE(q.Push(1));
    EXPECT_TRUE(q.Push(2));
    std::vector<int> out;
    EXPECT_EQ(q.Drain(out), 2u);
    EXPECT_EQ(out, (std::vector<int>{1, 2}));
    EXPECT_EQ(q.Size(), 0u);
}

TEST(TaskQueueTest, RejectsWhenFull) {
    BoundedTaskQueue<int> q(2);
    EXPECT_TRUE(q.Push(1));
    EXPECT_TRUE(q.Push(2));
    EXPECT_FALSE(q.Push(3));
}

TEST(TaskQueueTest, ConcurrentProducersLoseNothingBelowCapacity) {
    BoundedTaskQueue<int> q(4000);
    std::vector<std::thread> producers;
    for (int t = 0; t < 4; ++t) {
        producers.emplace_back([&q, t] { for (int i = 0; i < 1000; ++i) ASSERT_TRUE(q.Push(t * 1000 + i)); });
    }
    for (auto& p : producers) p.join();
    std::vector<int> out;
    EXPECT_EQ(q.Drain(out), 4000u);
}

TEST(TaskQueueTest, DrainAppendsAndAnEmptyDrainTakesNothing) {
    BoundedTaskQueue<int> q(4);
    std::vector<int> out{9};
    EXPECT_EQ(q.Drain(out), 0u);
    EXPECT_EQ(out, (std::vector<int>{9}));
    EXPECT_TRUE(q.Push(1));
    EXPECT_EQ(q.Drain(out), 1u);
    EXPECT_EQ(out, (std::vector<int>{9, 1}));
}

TEST(TaskQueueTest, AcceptsPushesAgainAfterADrain) {
    BoundedTaskQueue<int> q(1);
    EXPECT_TRUE(q.Push(1));
    EXPECT_FALSE(q.Push(2));
    EXPECT_EQ(q.Size(), 1u);
    std::vector<int> out;
    EXPECT_EQ(q.Drain(out), 1u);
    EXPECT_TRUE(q.Push(3));
}

TEST(TaskQueueTest, HoldsMoveOnlyItems) {
    BoundedTaskQueue<std::unique_ptr<int>> q(2);
    EXPECT_TRUE(q.Push(std::make_unique<int>(7)));
    std::vector<std::unique_ptr<int>> out;
    EXPECT_EQ(q.Drain(out), 1u);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(*out[0], 7);
}
