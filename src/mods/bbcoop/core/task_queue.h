// SPDX-FileCopyrightText: 2026 BB Co-op contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <atomic>
#include <cstddef>
#include <mutex>
#include <utility>
#include <vector>

namespace BBCoop::Core {

/// Multi-producer queue drained by a single consumer (the game thread). Producers get `false`
/// when the queue is full. The consumer never waits: Drain returns at once when the queue looks
/// empty and when a producer holds the lock at that instant (the items are taken by the next
/// Drain), and once the buffers have grown to the working size neither side allocates.
template <typename T>
class BoundedTaskQueue {
public:
    explicit BoundedTaskQueue(std::size_t capacity) : capacity_(capacity) {}

    bool Push(T item) {
        std::scoped_lock lock(mutex_);
        if (items_.size() >= capacity_) {
            return false;
        }
        items_.push_back(std::move(item));
        size_hint_.store(items_.size(), std::memory_order_relaxed);
        return true;
    }

    /// Moves everything queued so far to the end of `out`, in push order, and returns how many
    /// items that was. Single consumer only. May return 0 although items are queued, when a
    /// producer is inside Push; call it again next frame.
    std::size_t Drain(std::vector<T>& out) {
        if (size_hint_.load(std::memory_order_relaxed) == 0) {
            return 0;
        }
        {
            std::unique_lock lock(mutex_, std::try_to_lock);
            if (!lock.owns_lock()) {
                return 0;
            }
            // `taken_` is empty here and keeps its capacity: after the swap it becomes the
            // producers' buffer and the full buffer is ours.
            taken_.swap(items_);
            size_hint_.store(0, std::memory_order_relaxed);
        }
        const auto count = taken_.size();
        for (auto& item : taken_) {
            out.push_back(std::move(item));
        }
        taken_.clear();
        return count;
    }

    /// The exact number of queued items; takes the lock.
    std::size_t Size() const {
        std::scoped_lock lock(mutex_);
        return items_.size();
    }

private:
    mutable std::mutex mutex_;
    std::vector<T> items_;                  ///< Guarded by mutex_.
    std::vector<T> taken_;                  ///< The consumer's buffer; consumer only.
    std::atomic<std::size_t> size_hint_{0}; ///< items_.size(), written under mutex_.
    std::size_t capacity_;
};

} // namespace BBCoop::Core
