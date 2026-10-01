// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <array>
#include <atomic>
#include <chrono>
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
        producers.emplace_back([&q, t] {
            for (int i = 0; i < 1000; ++i)
                ASSERT_TRUE(q.Push(t * 1000 + i));
        });
    }
    for (auto& p : producers)
        p.join();
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

TEST(TaskQueueTest, ProducersAndADrainingConsumerDeliverEverythingOnceInOrder) {
    constexpr int kProducers = 4;
    constexpr int kPerProducer = 5000;
    constexpr std::size_t kTotal = kProducers * kPerProducer;
    // Small, so the producers keep running into a full queue while the consumer drains.
    BoundedTaskQueue<int> q(32);
    std::atomic<bool> stop{false};
    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&q, &stop, p] {
            for (int i = 0; i < kPerProducer; ++i) {
                while (!q.Push(p * kPerProducer + i)) {
                    if (stop) {
                        return;
                    }
                    std::this_thread::yield();
                }
            }
        });
    }

    std::vector<int> out;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (out.size() < kTotal && std::chrono::steady_clock::now() < deadline) {
        if (q.Drain(out) == 0) {
            std::this_thread::yield();
        }
    }
    stop = true;
    for (auto& producer : producers) {
        producer.join();
    }

    ASSERT_EQ(out.size(), kTotal);
    // Every value exactly once and, per producer, in the order it was pushed: the i-th value seen
    // from producer p must be p * kPerProducer + i.
    std::array<int, kProducers> next{};
    int misordered = 0;
    for (const int value : out) {
        const int producer = value / kPerProducer;
        if (producer < 0 || producer >= kProducers || value % kPerProducer != next[producer]++) {
            ++misordered;
        }
    }
    EXPECT_EQ(misordered, 0);
    EXPECT_EQ(q.Size(), 0u);
}
